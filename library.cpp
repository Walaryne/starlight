#include <iostream>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <dlfcn.h>

#include "offsets.h"


struct gateway_info {
	void *addr;
	std::string name;
};

struct gateway_info *gateways;
void *gateway_entries;
void *trampolines;

namespace starlight {
	void pinfo(const char buf[]) {
		printf("[Starlight]: %s\n", buf);
	}

	unsigned long get_base_pointer() {
		auto* lm = (struct link_map *) dlopen(nullptr, RTLD_NOW);
		return (unsigned long)lm -> l_addr;
	}

	void *write_trampoline(void *function, void *trampolines, void *return_pointer, unsigned long long offset) {
		unsigned char bytes[] {
			//0x9c, // PUSHFQ
			//0x57, // Push RDI
			//0x56, // Push RSI
			//0x52, // Push RDX
			//0x51, // Push RCX
			//0x41, 0x50, // Push R8
			//0x41, 0x51, // Push R9
			0x48, 0xb8, // movabs RAX, --
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // reserved
			0xff, 0xd0, // call RAX
			//0x41, 0x59, // Pop R9
			//0x41, 0x58, // Pop R8
			//0x59, // Pop RCX
			//0x5a, // Pop RDX
			//0x5e, // Pop RSI
			//0x5f, // Pop RDI
			//0x9d, // POPFQ
			0x48, 0xb8, // movabs RAX --
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // reserved
			0xff, 0xe0 // jmp RAX
		};

		//*(unsigned long long *)(bytes + 11) = (unsigned long long) function;
		//*(unsigned long long *)(bytes + 40) = (unsigned long long) return_pointer;

		*(unsigned long long *)(bytes + 2) = (unsigned long long) function;
		*(unsigned long long *)(bytes + 22) = (unsigned long long) return_pointer;

		memcpy(trampolines, bytes, sizeof(bytes));

		return trampolines;
	}

	gateway_info injector(std::string name, unsigned long long addr, void *function, unsigned long bytes_length, unsigned long gateway_offset) {
		unsigned long long corrected_addr = addr + get_base_pointer();
		long pagesize = sysconf(_SC_PAGESIZE);
		void *aligned_address = (void *)(corrected_addr & ~(pagesize - 1));
		int retval = mprotect(aligned_address, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
		gateway_info gi;

		if(retval == 0) {
			pinfo("SUCCESSFULLY UNLOCKED MEMORY");

			memcpy(gateway_entries, (void *) corrected_addr, bytes_length);

			*(short *)(corrected_addr + 0x0) = (short) 0xb848;
			*(unsigned long long *)(corrected_addr + 0x02) = (unsigned long long) function;
			*(short *)(corrected_addr + 0xa) = (short) 0xe0ff;

			printf("[Starlight]: Overwrote instructions at %p\n", (void *) corrected_addr);

			gi.addr = gateway_entries;
			gi.name = name;

			unsigned long long gateway_pointer = (unsigned long long) gateway_entries + gateway_offset + bytes_length;
			*(short *)(gateway_pointer + 0x0) = (short) 0xb848;
			*(unsigned long long *)(gateway_pointer + 0x02) = corrected_addr + bytes_length;
			*(short *)(gateway_pointer + 0xa) = (short) 0xe0ff;

		} else {
			gi.addr = 0;
			gi.name = "null";

			pinfo("ERROR UNLOCKING MEMORY");
		}

		mprotect(aligned_address, pagesize, PROT_READ | PROT_EXEC);
		pinfo("SUCCESSFULLY RE-LOCKED MEMORY");

		return gi;
	}
}

typedef __cdecl void *(*doChatOriginal)(void *, std::string *, bool);

doChatOriginal doChat;

void __cdecl doChatHook(void *thispointer, std::string *p1, bool p2) {
	starlight::pinfo("Called doChatHook");
	starlight::pinfo(p1->c_str());
	//*(&p2) = false;
	starlight::pinfo(p2 ? "true" : "false");

	if(p1->front() == '.') {
		starlight::pinfo("dotcommand attempted");
		return;
	}

	doChat(thispointer, p1, p2);
}

__attribute__((constructor))
void entry() {
	starlight::pinfo("Starlight Injected");
	gateways = static_cast<gateway_info *>(malloc(sizeof(gateway_info *) * 30));
	gateway_entries = mmap(0, sysconf(_SC_PAGESIZE), PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0x0);
	trampolines = mmap(0, sysconf(_SC_PAGESIZE), PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0x0);
	
	if(gateway_entries == MAP_FAILED) {
		perror("mmap gateway_entries");
	}

	if(trampolines == MAP_FAILED) {
		perror("mmap trampolines");
	}

	printf("[Starlight]: mmap is at %p\n", gateway_entries);
	void *function = starlight::write_trampoline((void *) doChatHook, trampolines, (void *) DO_CHAT_RET, 0x0);
	gateway_info info = starlight::injector("commands", DO_CHAT, function, 17, 0x0);

	doChat = (doChatOriginal) info.addr;
}
