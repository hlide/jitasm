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
        size_t count = ::cs_disasm(handle, (uint8_t const *)code, size, (uint64_t)code, 0, &insn);
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

#if 1
        AppendInstr(I_AAA);
        AppendInstr(I_AAD);
        AppendInstr(I_AAM);
        AppendInstr(I_AAS);

        AppendInstr(I_ADC, al, dl);
        AppendInstr(I_ADC, ax, dx);
        AppendInstr(I_ADC, eax, edx);
        AppendInstr(I_ADC, byte_ptr[edx + ebx * 2 + 16], al);
        AppendInstr(I_ADC, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_ADC, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_ADC, al, byte_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADC, ax, word_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADC, eax, dword_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADC, al, i8);
        AppendInstr(I_ADC, dl, i8);
        AppendInstr(I_ADC, ax, i16);
        AppendInstr(I_ADC, dx, i16);
        AppendInstr(I_ADC, eax, i32);
        AppendInstr(I_ADC, edx, i32);
        AppendInstr(I_ADC, dx, i8);
        AppendInstr(I_ADC, edx, i8);

        AppendInstr(I_ADD, al, dl);
        AppendInstr(I_ADD, ax, dx);
        AppendInstr(I_ADD, eax, edx);
        AppendInstr(I_ADD, byte_ptr[edx + ebx * 2 + 16], al);
        AppendInstr(I_ADD, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_ADD, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_ADD, al, byte_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADD, ax, word_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADD, eax, dword_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADD, al, i8);
        AppendInstr(I_ADD, dl, i8);
        AppendInstr(I_ADD, ax, i16);
        AppendInstr(I_ADD, dx, i16);
        AppendInstr(I_ADD, eax, i32);
        AppendInstr(I_ADD, edx, i32);
        AppendInstr(I_ADD, dx, i8);
        AppendInstr(I_ADD, edx, i8);

        AppendInstr(I_ADX, i8);
        AppendInstr(I_AMX, i8);
        
        AppendInstr(I_AND, al, dl);
        AppendInstr(I_AND, ax, dx);
        AppendInstr(I_AND, eax, edx);
        AppendInstr(I_AND, byte_ptr[edx + ebx * 2 + 16], al);
        AppendInstr(I_AND, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_AND, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_AND, al, byte_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_AND, ax, word_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_AND, eax, dword_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_AND, al, i8);
        AppendInstr(I_AND, dl, i8);
        AppendInstr(I_AND, ax, i16);
        AppendInstr(I_AND, dx, i16);
        AppendInstr(I_AND, eax, i32);
        AppendInstr(I_AND, edx, i32);
        AppendInstr(I_AND, dx, i8);
        AppendInstr(I_AND, edx, i8);

        AppendInstr(I_ARPL, word_ptr[edx + ebx * 2 + 16], ax);

        AppendInstr(I_BOUND, ax, dword_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_BOUND, eax, qword_ptr[edx + ebx * 2 + 16]);

        AppendInstr(I_BSF, ax, dx);
        AppendInstr(I_BSF, eax, edx);
        AppendInstr(I_BSF, ax, word_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_BSF, eax, dword_ptr[edx + ebx * 2 + 16]);

        AppendInstr(I_BSR, ax, dx);
        AppendInstr(I_BSR, eax, edx);
        AppendInstr(I_BSR, ax, word_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_BSR, eax, dword_ptr[edx + ebx * 2 + 16]);

        AppendInstr(I_BSWAP, eax);

        AppendInstr(I_BT, ax, dx);
        AppendInstr(I_BT, eax, edx);
        AppendInstr(I_BT, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_BT, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_BT, ax, i8);
        AppendInstr(I_BT, eax, i8);
        AppendInstr(I_BT, word_ptr[edx + ebx * 2 + 16], i8);
        AppendInstr(I_BT, dword_ptr[edx + ebx * 2 + 16], i8);

        AppendInstr(I_BTC, ax, dx);
        AppendInstr(I_BTC, eax, edx);
        AppendInstr(I_BTC, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_BTC, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_BTC, ax, i8);
        AppendInstr(I_BTC, eax, i8);
        AppendInstr(I_BTC, word_ptr[edx + ebx * 2 + 16], i8);
        AppendInstr(I_BTC, dword_ptr[edx + ebx * 2 + 16], i8);

        AppendInstr(I_BTR, ax, dx);
        AppendInstr(I_BTR, eax, edx);
        AppendInstr(I_BTR, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_BTR, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_BTR, ax, i8);
        AppendInstr(I_BTR, eax, i8);
        AppendInstr(I_BTR, word_ptr[edx + ebx * 2 + 16], i8);
        AppendInstr(I_BTR, dword_ptr[edx + ebx * 2 + 16], i8);

        AppendInstr(I_BTS, ax, dx);
        AppendInstr(I_BTS, eax, edx);
        AppendInstr(I_BTS, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_BTS, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_BTS, ax, i8);
        AppendInstr(I_BTS, eax, i8);
        AppendInstr(I_BTS, word_ptr[edx + ebx * 2 + 16], i8);
        AppendInstr(I_BTS, dword_ptr[edx + ebx * 2 + 16], i8);

        AppendInstr(I_CALL, Imm16(0));
        AppendInstr(I_CALL, Imm32(0));
        AppendInstr(I_CALL, ax);
        AppendInstr(I_CALL, eax);

        AppendInstr(I_CBW);
        AppendInstr(I_CWDE);
        AppendInstr(I_CDQ);
        AppendInstr(I_CLC);
        AppendInstr(I_CLD);
        AppendInstr(I_CLI);
        AppendInstr(I_CMC);

        for (size_t cc = 0; cc < 16; ++cc)
        {
            AppendCondInstr(I_CMOVcc, ConditionCode(cc), ax, dx);
            AppendCondInstr(I_CMOVcc, ConditionCode(cc), eax, edx);
            AppendCondInstr(I_CMOVcc, ConditionCode(cc), ax, word_ptr[edx + ebx * 2 + 16]);
            AppendCondInstr(I_CMOVcc, ConditionCode(cc), eax, dword_ptr[edx + ebx * 2 + 16]);
        }

        AppendInstr(I_CMP, al, dl);
        AppendInstr(I_CMP, ax, dx);
        AppendInstr(I_CMP, eax, edx);
        AppendInstr(I_CMP, byte_ptr[edx + ebx * 2 + 16], al);
        AppendInstr(I_CMP, word_ptr[edx + ebx * 2 + 16], ax);
        AppendInstr(I_CMP, dword_ptr[edx + ebx * 2 + 16], eax);
        AppendInstr(I_CMP, al, byte_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_CMP, ax, word_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_CMP, eax, dword_ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_CMP, al, i8);
        AppendInstr(I_CMP, dl, i8);
        AppendInstr(I_CMP, ax, i16);
        AppendInstr(I_CMP, dx, i16);
        AppendInstr(I_CMP, eax, i32);
        AppendInstr(I_CMP, edx, i32);
        AppendInstr(I_CMP, dx, i8);
        AppendInstr(I_CMP, edx, i8);

        AppendInstr(I_CMPS_B);
        AppendInstr(I_CMPS_W);
        AppendInstr(I_CMPS_D);

        // Group LZCNT
        AppendInstr(I_LZCNT, eax, edx);
        AppendInstr(I_LZCNT, eax, ptr[edx + ebx * 2 + 16]);

        // Group BIM1
        AppendInstr(I_ANDN, eax, edx, ecx);
        AppendInstr(I_ANDN, eax, edx, ptr[ecx + ebx * 2 + 16]);
        AppendInstr(I_BEXTR, eax, edx, ecx);
        AppendInstr(I_BEXTR, eax, ptr[edx + ebx * 2 + 16], ecx);
        AppendInstr(I_BLSI, eax, ecx);
        AppendInstr(I_BLSI, eax, ptr[ecx + ebx * 2 + 16]);
        AppendInstr(I_BLSMSK, eax, ecx);
        AppendInstr(I_BLSMSK, eax, ptr[ecx + ebx * 2 + 16]);
        AppendInstr(I_BLSR, eax, ecx);
        AppendInstr(I_BLSR, eax, ptr[ecx + ebx * 2 + 16]);
        AppendInstr(I_TZCNT, eax, edx);
        AppendInstr(I_TZCNT, eax, ptr[edx + ebx * 2 + 16]);

        // Group BIM2
        AppendInstr(I_BZHI, eax, edx, ecx);
        AppendInstr(I_BZHI, eax, ptr[edx + ebx * 2 + 16], ecx);
        AppendInstr(I_MULX, eax, ecx, edx, ebx);
        AppendInstr(I_MULX, eax, ecx, edx, ptr[esi + ebx * 2 + 16]);
        AppendInstr(I_PDEP, eax, edx, ecx);
        AppendInstr(I_PDEP, eax, edx, ptr[ecx + ebx * 2 + 16]);
        AppendInstr(I_PEXT, eax, edx, ecx);
        AppendInstr(I_PEXT, eax, edx, ptr[ecx + ebx * 2 + 16]);
        AppendInstr(I_RORX, eax, edx, Imm8(8));
        AppendInstr(I_RORX, eax, ptr[edx + ebx * 2 + 16], Imm8(8));
        AppendInstr(I_SARX, eax, edx, ecx);
        AppendInstr(I_SARX, eax, ptr[edx + ebx * 2 + 16], ecx);
        AppendInstr(I_SHLX, eax, edx, ecx);
        AppendInstr(I_SHLX, eax, ptr[edx + ebx * 2 + 16], ecx);
        AppendInstr(I_SHRX, eax, edx, ecx);
        AppendInstr(I_SHRX, eax, ptr[edx + ebx * 2 + 16], ecx);

        // Group ADX
        AppendInstr(I_ADCX, eax, edx);
        AppendInstr(I_ADCX, eax, ptr[edx + ebx * 2 + 16]);
        AppendInstr(I_ADOX, eax, edx);
        AppendInstr(I_ADOX, eax, ptr[edx + ebx * 2 + 16]);
#endif

        //AppendInstr(I_MOV, al, ptr[0x55555555]);
        //AppendInstr(I_MOV, ax, ptr[0x55555555]);
        //AppendInstr(I_MOV, eax, ptr[0x55555555]);
        //AppendInstr(I_MOV, ptr[0x55555555], al);
        //AppendInstr(I_MOV, ptr[0x55555555], ax);
        //AppendInstr(I_MOV, ptr[0x55555555], eax);
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

#if 1
        AppendInstr(I_ADC, rax, rdx);
        AppendInstr(I_ADC, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_ADC, rax, qword_ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_ADC, rax, i32);
        AppendInstr(I_ADC, rdx, i32);
        AppendInstr(I_ADC, rdx, i8);

        AppendInstr(I_ADD, rax, rdx);
        AppendInstr(I_ADD, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_ADD, rax, qword_ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_ADD, rax, i32);
        AppendInstr(I_ADD, rdx, i32);
        AppendInstr(I_ADD, rdx, i8);

        AppendInstr(I_AND, rax, rdx);
        AppendInstr(I_AND, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_AND, rax, qword_ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_AND, rax, i32);
        AppendInstr(I_AND, rdx, i32);
        AppendInstr(I_AND, rdx, i8);

        AppendInstr(I_BOUND, rax, qword_ptr[rdx + rbx * 2 + 16]);

        AppendInstr(I_BSF, rax, rdx);
        AppendInstr(I_BSF, rax, qword_ptr[rdx + rbx * 2 + 16]);

        AppendInstr(I_BSR, rax, rdx);
        AppendInstr(I_BSR, rax, qword_ptr[rdx + rbx * 2 + 16]);

        AppendInstr(I_BSWAP, rax);

        AppendInstr(I_BT, rax, rdx);
        AppendInstr(I_BT, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_BT, rax, i8);
        AppendInstr(I_BT, qword_ptr[rdx + rbx * 2 + 16], i8);

        AppendInstr(I_BTC, rax, rdx);
        AppendInstr(I_BTC, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_BTC, rax, i8);
        AppendInstr(I_BTC, qword_ptr[rdx + rbx * 2 + 16], i8);

        AppendInstr(I_BTR, rax, rdx);
        AppendInstr(I_BTR, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_BTR, rax, i8);
        AppendInstr(I_BTR, qword_ptr[rdx + rbx * 2 + 16], i8);

        AppendInstr(I_BTS, rax, rdx);
        AppendInstr(I_BTS, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_BTS, rax, i8);
        AppendInstr(I_BTS, qword_ptr[rdx + rbx * 2 + 16], i8);

        AppendInstr(I_CDQE);

        for (size_t cc = 0; cc < 16; ++cc)
        {
            AppendCondInstr(I_CMOVcc, ConditionCode(cc), rax, rdx);
            AppendCondInstr(I_CMOVcc, ConditionCode(cc), rax, qword_ptr[rdx + rbx * 2 + 16]);
        }

        AppendInstr(I_CMP, rax, rdx);
        AppendInstr(I_CMP, qword_ptr[rdx + rbx * 2 + 16], rax);
        AppendInstr(I_CMP, rax, qword_ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_CMP, rax, i32);
        AppendInstr(I_CMP, rdx, i32);
        AppendInstr(I_CMP, rdx, i8);

        AppendInstr(I_CMPS_Q);

        AppendInstr(I_ADCX, rax, rdx);
        AppendInstr(I_ADCX, rax, ptr[rdx + rbx * 2 + 16]);
        AppendInstr(I_ADOX, rax, rdx);
        AppendInstr(I_ADOX, rax, ptr[rdx + rbx * 2 + 16]);

        AppendInstr(I_MOV, al, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, ax, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, eax, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, rax, ptr[0x5555555555555555]);
        AppendInstr(I_MOV, ptr[0x5555555555555555], al);
        AppendInstr(I_MOV, ptr[0x5555555555555555], ax);
        AppendInstr(I_MOV, ptr[0x5555555555555555], eax);
        AppendInstr(I_MOV, ptr[0x5555555555555555], rax);
#endif
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

    system("pause");

    return 0;
}