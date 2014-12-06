#include <windows.h>

#include "jitasm.Frontend.x86_32.h"
#include "jitasm.Frontend.x86_64.h"
#pragma comment(lib, "x64/release/jitasm.lib")

#include "capstone/include/capstone.h"
#pragma comment(lib, "capstone/lib/capstone.lib")

static void capstone_Disassemble(FILE * out, cs_insn & insn)
{
	char address[32];

	//sprintf(address, "0x%08llX(%2d):", insn.address, insn.size);

	sprintf(address, "(%2d):", insn.size);

	char bytes[64], *p = bytes;

	for (size_t i = 0; i < insn.size; ++i)
	{
		p += sprintf(p, "%02X", size_t(insn.bytes[insn.size - i - 1]));
	}

	//fprintf(out, "%s %32s %-16s %s\r\n", address, bytes, insn.mnemonic, insn.op_str);
	fprintf(out, "%s %16s %-8s %s\r\n", address, bytes, insn.mnemonic, insn.op_str);
}

static void capstone_Dump(FILE * out, cs_mode mode, void * code, size_t size)
{
	cs_insn * insn;
	csh handle;
	cs_err err = ::cs_open(CS_ARCH_X86, mode, &handle);

	if (CS_ERR_OK == err)
	{
		size_t count = ::cs_disasm(handle, (uint8_t const *)code, size, (uint64_t)code, 0, &insn);
		if (count > 0)
		{
			for (size_t j = 0; j < count; ++j)
			{
				capstone_Disassemble(out, insn[j]);
			}
			::cs_free(insn, count);
		}

		::cs_close(&handle);
	}
}

class CriticalSection : CRITICAL_SECTION
{
public:
    CriticalSection()
    {
        ::InitializeCriticalSection(this);
    }

    ~CriticalSection()
    {
        ::DeleteCriticalSection(this);
    }

    void Enter()
    {
        ::EnterCriticalSection(this);
    }

    void Leave()
    {
        ::LeaveCriticalSection(this);
    }
};

/** @brief   The RTL create heap. */
static auto RtlCreateHeap =
(PVOID (NTAPI *)(
	_In_      ULONG Flags,
	_In_opt_  PVOID HeapBase,
	_In_opt_  SIZE_T ReserveSize,
	_In_opt_  SIZE_T CommitSize,
	_In_opt_  PVOID Lock,
	_In_opt_  PVOID Parameters
	))::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "RtlCreateHeap");

static auto RtlAllocateHeap =
(PVOID (NTAPI *)(
	_In_      PVOID HeapHandle,
	_In_opt_  ULONG Flags,
	_In_      SIZE_T Size
    ))::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "RtlAllocateHeap");

static auto RtlFreeHeap =
(BOOLEAN (NTAPI *)(
	_In_      PVOID HeapHandle,
	_In_opt_  ULONG Flags,
	_In_      PVOID HeapBase
    ))::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "RtlFreeHeap");

static auto RtlDestroyHeap =
(PVOID (NTAPI *)(
	_In_  PVOID HeapHandle
    ))::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "RtlDestroyHeap");

struct CodeBuffer : jitasm::CodeBuffer$CRTP< CodeBuffer >
{
	bool AllocateBuffer(size_t codesize)
	{
        void * p = ::RtlAllocateHeap(heap_, 0, codesize);
        if (p)
        {
            buffaddr_ = p;
            buffsize_ = codesize;
        }
        return !!p;
	}

	bool FreeBuffer()
	{
        return TRUE == ::RtlFreeHeap(heap_, 0, buffaddr_);
	}

    CodeBuffer()
    {
        if (0 == _InterlockedExchangeAdd(&refs_, 1))
        {
            cs_.Enter();
            if (!filemapping_)
            {
                size_t size = 64 * 1024 * 1024; // 64 Mbyte
                bool ok = 0 != (filemapping_ = ::CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, SEC_COMMIT | PAGE_EXECUTE_READWRITE, 0, (DWORD)size, NULL));
                if (ok)
                {
                    ok = 0 != (base_ = ::MapViewOfFileEx(filemapping_, FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, size, (LPVOID)0));
                    if (ok)
                    {
                        ok = 0 != (heap_ = ::RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE | HEAP_CREATE_ALIGN_16 | HEAP_GENERATE_EXCEPTIONS, base_, size, 0, NULL, NULL));

                        if (!ok)
                        {
                            ::UnmapViewOfFile(base_);
                            base_ = 0;
                        }
                    }
                    if (!ok)
                    {
                        ::CloseHandle(filemapping_);
                        filemapping_ = 0;
                    }
                }
            }
            cs_.Leave();
        }
    }

    ~CodeBuffer()
    {
        if (1 == _InterlockedExchangeAdd(&refs_, -1))
        {
            cs_.Enter();
            if (filemapping_)
            {
                if (heap_)
                {
                    ::RtlDestroyHeap(heap_);
                    heap_ = 0;
                }

                if (base_)
                {
                    ::UnmapViewOfFile(base_);
                    base_ = 0;
                }

                ::CloseHandle(filemapping_);
                filemapping_ = 0;
            }
            cs_.Leave();
        }
    }

	static HANDLE           heap_;
    static HANDLE           filemapping_;
    static void           * base_;
    static CriticalSection  cs_;
    static long             refs_;
    static CodeBuffer       singleton_;
};

HANDLE          CodeBuffer::heap_ = 0;
HANDLE          CodeBuffer::filemapping_ = 0;
void          * CodeBuffer::base_ = 0;
CriticalSection CodeBuffer::cs_;
long            CodeBuffer::refs_ = 0;
CodeBuffer      CodeBuffer::singleton_;

struct Frontend_x86_32 : jitasm::x86_32::Frontend$CRTP< Frontend_x86_32 >, CodeBuffer
{
    typedef ::CodeBuffer CodeBuffer;

    void InternalMain()
	{
		using namespace jitasm::x86_32;

		Imm8  i8(0x55);
		Imm16 i16(0x5555);
		Imm32 i32(0x55555555);

		AppendInstr(I_ADD, al, i8);
		AppendInstr(I_ADD, ax, i16);
		AppendInstr(I_ADD, eax, i32);
		
        AppendInstr(I_ALIGN, Imm8(5));

		AppendInstr(I_ADD, ax, i8);
		AppendInstr(I_ADD, eax, i8);
		
		AppendInstr(I_ADD, dl, i8);
		AppendInstr(I_ADD, dx, i16);
		AppendInstr(I_ADD, edx, i32);

		AppendInstr(I_ADD, dx, i8);
		AppendInstr(I_ADD, edx, i8);
		
		AppendInstr(I_ADD, al, dl);
		AppendInstr(I_ADD, ax, dx);
		AppendInstr(I_ADD, eax, edx);

		AppendInstr(I_ADD, eax, ptr[edx + ebx * 2 + 16]);
		AppendInstr(I_ADD, ptr[edx + ebx * 2 + 16], eax);

        AppendInstr(I_MOV, al, ptr[0x55555555]);
        AppendInstr(I_MOV, ax, ptr[0x55555555]);
        AppendInstr(I_MOV, eax, ptr[0x55555555]);
        AppendInstr(I_MOV, ptr[0x55555555], al);
        AppendInstr(I_MOV, ptr[0x55555555], ax);
        AppendInstr(I_MOV, ptr[0x55555555], eax);
    }
};

struct Frontend_x86_64 : jitasm::x86_64::Frontend$CRTP< Frontend_x86_64 >, CodeBuffer
{
    typedef ::CodeBuffer CodeBuffer;

    void InternalMain()
	{
		using namespace jitasm::x86_64;

        Imm8  i8(0x55);
        Imm16 i16(0x5555);
        Imm32 i32(0x55555555);

        AppendInstr(I_ADD, al, i8);
        AppendInstr(I_ADD, ax, i16);
        AppendInstr(I_ADD, eax, i32);
        AppendInstr(I_ADD, rax, i32);

        AppendInstr(I_ADD, ax, i8);
        AppendInstr(I_ADD, eax, i8);
        AppendInstr(I_ADD, rax, i8);

        AppendInstr(I_ADD, dl, i8);
        AppendInstr(I_ADD, dx, i16);
        AppendInstr(I_ADD, edx, i32);
        AppendInstr(I_ADD, rdx, i32);

        AppendInstr(I_ADD, dx, i8);
        AppendInstr(I_ADD, edx, i8);
        AppendInstr(I_ADD, rdx, i8);

        AppendInstr(I_ADD, al, dl);
        AppendInstr(I_ADD, ax, dx);
        AppendInstr(I_ADD, eax, edx);
        AppendInstr(I_ADD, rax, rdx);

        AppendInstr(I_ADD, eax, ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_ADD, rax, ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_ADD, ptr[rdx + rbx * 2 + 16], eax);
        AppendInstr(I_ADD, ptr[rdx + rbx * 2 + 16], rax);

        AppendInstr(I_MOV, al, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, ax, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, eax, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, rax, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, ptr[0x5555555555555555], al);
        AppendInstr(I_MOV, ptr[0x5555555555555555], ax);
        AppendInstr(I_MOV, ptr[0x5555555555555555], eax);
        AppendInstr(I_MOV, ptr[0x5555555555555555], rax);
        //AppendInstr(I_ADD, eax, rip_ptr[16]);
	}
};

void test_x86()
{
	Frontend_x86_32 x86;

    void * code = x86.GetCodePointer();
    size_t size = x86.GetCodeSize();

	fprintf(stdout, "test_x86:\r\n=========\r\n");
	capstone_Dump(stdout, CS_MODE_32, code, size);
	fprintf(stdout, "\r\n");
}

void test_x64()
{
	Frontend_x86_64 x64;

    void * code = x64.GetCodePointer();
    size_t size = x64.GetCodeSize();

    fprintf(stdout, "test_x64:\r\n=========\r\n");
	capstone_Dump(stdout, CS_MODE_64, code, size);
	fprintf(stdout, "\r\n");
}

int main(int argc, char * argv[])
{
	test_x86();

	test_x64();

	return 0;
}