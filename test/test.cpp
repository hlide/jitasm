#include <windows.h>

#include "jitasm.Frontend.x86_32.h"
#include "jitasm.Frontend.x86_64.h"

#include "capstone/include/capstone.h"
#if defined(NDEBUG)
#   if defined(_WIN64) 
#       pragma comment(lib, "x64/release/jitasm.lib")
#       pragma comment(lib, "capstone/lib/capstone.release.x86_64.lib")
#   else
#       pragma comment(lib, "release/jitasm.lib")
#       pragma comment(lib, "capstone/lib/capstone.release.x86_32.lib")
#   endif
#else
#   if defined(_WIN64) 
#       pragma comment(lib, "x64/debug/jitasm.lib")
#       pragma comment(lib, "capstone/lib/capstone.debug.x86_64.lib")
#   else
#       pragma comment(lib, "debug/jitasm.lib")
#       pragma comment(lib, "capstone/lib/capstone.debug.x86_32.lib")
#   endif
#endif

static void capstone_Disassemble(FILE * out, cs_insn & insn)
{
    char address[32];

    sprintf(address, "0x%08llX(%2d):", insn.address, insn.size);

    char bytes[64], *p = bytes;

    for (size_t i = 0; i < insn.size; ++i)
    {
        p += sprintf(p, "%02X", size_t(insn.bytes[insn.size - i - 1]));
    }

    fprintf(out, "%s %32s %-16s %s\r\n", address, bytes, insn.mnemonic, insn.op_str);
}

static void capstone_Dump(FILE * out, cs_mode mode, void * code, size_t size)
{
    cs_insn * insn;
    csh handle;
    cs_err err = ::cs_open(CS_ARCH_X86, mode, &handle);

    if (CS_ERR_OK == err)
    {
        size_t count = ::cs_disasm(handle, (uint8_t const *)code, size, (uint64_t)0x10000000, 0, &insn);
        if (count > 0)
        {
            for (size_t j = 0; j < count; ++j)
            {
                capstone_Disassemble(out, insn[j]);
                size = size - insn[j].size;
                code = (void *)((uint8_t *)code + insn[j].size);
            }
            ::cs_free(insn, count);
        }

        if (size)
        {
            char address[32];

            size = min(size, 16);

            sprintf(address, "(%2d):", size);

            char bytes[64], *p = bytes;

            for (size_t i = 0; i < size; ++i)
            {
                p += sprintf(p, "%02X", size_t(((uint8_t const *)code)[i]));
            }

            fprintf(out, "%s %16s unknown instruction(s)\r\n", address, bytes);
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
    void InternalMain()
    {
        using namespace jitasm::x86_32;

        Imm8  i8(0x55);
        Imm16 i16(0x5555);
        Imm32 i32(0x55555555);

        AppendInstr(I_ADD, dl, i8);
        AppendInstr(I_OR, dl, i8);
        AppendInstr(I_ADC, dl, i8);
        AppendInstr(I_SBB, dl, i8);
        AppendInstr(I_AND, dl, i8);
        AppendInstr(I_SUB, dl, i8);
        AppendInstr(I_XOR, dl, i8);
        AppendInstr(I_CMP, dl, i8);

        AppendInstr(I_ADD, byte_ptr[0x55555555], i8);
        AppendInstr(I_OR, byte_ptr[0x55555555], i8);
        AppendInstr(I_ADC, byte_ptr[0x55555555], i8);
        AppendInstr(I_SBB, byte_ptr[0x55555555], i8);
        AppendInstr(I_AND, byte_ptr[0x55555555], i8);
        AppendInstr(I_SUB, byte_ptr[0x55555555], i8);
        AppendInstr(I_XOR, byte_ptr[0x55555555], i8);
        AppendInstr(I_CMP, byte_ptr[0x55555555], i8);
    }
};

struct Frontend_x86_64 : jitasm::x86_64::Frontend$CRTP< Frontend_x86_64 >, CodeBuffer
{
    void InternalMain()
    {
        using namespace jitasm::x86_64;

        Imm8  i8(0x55);
        Imm16 i16(0x5555);
        Imm32 i32(0x55555555);
    }
};

void test_x86_32()
{
    Frontend_x86_32 x86_32;

    fprintf(stdout, "test_x86 - 32-bit mode:\r\n=========\r\n");

#if 1
    for (jitasm::x86::InstrID id = jitasm::x86::I_AAA; id <= jitasm::x86::I_XTEST; id = jitasm::x86::InstrID(size_t(id) + 1))
    {
        x86_32.Test(id);

        void * code = x86_32.GetCodePointer();
        size_t size = x86_32.GetCodeSize();

        if (size)
        {
            capstone_Dump(stdout, CS_MODE_32, code, size);
            fprintf(stdout, "\r\n");
        }
    }
#else
    void * code = x86_32.GetCodePointer();
    size_t size = x86_32.GetCodeSize();

    capstone_Dump(stdout, CS_MODE_32, code, size);
#endif

    fprintf(stdout, "\r\n");
}

void test_x86_64()
{
    Frontend_x86_64 x86_64;

    fprintf(stdout, "test_x86 - 64-bit mode:\r\n=========\r\n");
#if 1
    for (jitasm::x86::InstrID id = jitasm::x86::I_AAA; id <= jitasm::x86::I_XTEST; id = jitasm::x86::InstrID(size_t(id) + 1))
    {
        x86_64.Test(id);

        void * code = x86_64.GetCodePointer();
        size_t size = x86_64.GetCodeSize();

        if (size)
        {
            capstone_Dump(stdout, CS_MODE_64, code, size);
            fprintf(stdout, "\r\n");
        }
    }
#else
    void * code = x86_64.GetCodePointer();
    size_t size = x86_64.GetCodeSize();
    capstone_Dump(stdout, CS_MODE_64, code, size);
#endif
    fprintf(stdout, "\r\n");
}

int main(int argc, char * argv[])
{
    test_x86_32();

    test_x86_64();

    system("pause");

    return 0;
}