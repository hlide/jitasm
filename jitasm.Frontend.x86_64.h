#pragma once
#ifndef jitasm_Frontend_x86_64_h__
#define jitasm_Frontend_x86_x64_h__
#include "jitasm.x86.h"
#include "jitasm.x86_64.h"
#include "jitasm.Frontend.x86.h"
namespace jitasm
{
    namespace x86_64
    {
        namespace detail
        {
            using namespace jitasm::detail;

            /**
            * <b>Stack layout</b>
            * \verbatim
            * +-----------------------+
            * | Caller return address |
            * +=======================+========
            * |       ebp (rbp)       |
            * +-----------------------+ <-- ebp (rbp)
            * |  Saved gp registers   |
            * +-----------------------+
            * | Padding for alignment |
            * +-----------------------+ <-- Stack base
            * |    Spill slots and    |
            * |    local variable     |
            * +-----------------------+ <-- esp (rsp)
            * \endverbatim
            */
            class StackManager
            {
            private:
                Addr stack_base_;
                uint32 stack_size_;

            public:
                StackManager() : stack_base_(RegID::CreatePhysicalRegID(R_TYPE_GP, EBX), 0), stack_size_(0) {}

                /// Get allocated stack size
                uint32 GetSize() const { return (stack_size_ + 15) / 16 * 16; /* 16 bytes aligned*/ }

                /// Get stack base
                Addr GetStackBase() const { return stack_base_; }

                /// Set stack base
                void SetStackBase(const Addr& stack_base) { stack_base_ = stack_base; }

                /// Allocate stack
                Addr Alloc(uint32 size, uint32 alignment)
                {
                    stack_size_ = (stack_size_ + alignment - 1) / alignment * alignment;
                    stack_size_ += size;
                    return stack_base_ - stack_size_;
                }
            };
        }

        template < typename Derived > struct Frontend$CRTP : jitasm::x86::Frontend$CRTP< Derived > /* using Curiously Recurring Template Pattern */
        {
            typedef jitasm::x86::Addr64	Addr;
            typedef jitasm::x86::Reg64	Reg;

            Reg8					    r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b;
            Reg16				        r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w;
            Reg32				        r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d;
            Reg64				        rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
            XmmReg				        xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
            YmmReg				        ymm8, ymm9, ymm10, ymm11, ymm12, ymm13, ymm14, ymm15;
            Reg					        zax, zcx, zdx, zbx, zsp, zbp, zsi, zdi;

            AddressingPtr<Opd8>			byte_ptr;
            AddressingPtr<Opd16>		word_ptr;
            AddressingPtr<Opd32>		dword_ptr;
            AddressingPtr<Opd64>		qword_ptr;
            AddressingPtr<Opd64>		mmword_ptr;
            AddressingPtr<Opd128>		xmmword_ptr;
            AddressingPtr<Opd256>		ymmword_ptr;
            AddressingPtr<Opd32>		real4_ptr;
            AddressingPtr<Opd64>		real8_ptr;
            AddressingPtr<Opd80>		real10_ptr;
            AddressingPtr<Opd16>		m2byte_ptr;
            AddressingPtr<Opd224>		m28byte_ptr;
            AddressingPtr<Opd864>		m108byte_ptr;
            AddressingPtr<Opd4096>		m512byte_ptr;

            AddressingPtr<Opd64>		ptr;

            detail::StackManager	    stack_manager_;

            template < typename OpdN > struct RipPtr : AddressingPtr < OpdN >
            {
                Mem$< OpdN > operator[](uint32_t label_name)
                {
                    Mem$< OpdN > result(O_SIZE_64, O_SIZE_64, RegID::CreatePhysicalRegID(R_TYPE_IP, RIP), RegID::Invalid(), 0, 0);
                    switch (result.GetSize())
                    {
                    case O_SIZE_8:    return result[((Frontend*)((char*)this - offsetof(Frontend, byte_rip_ptr)))->GetLabelID(label_name)];
                    case O_SIZE_16:   return result[((Frontend*)((char*)this - offsetof(Frontend, word_rip_ptr)))->GetLabelID(label_name)];
                    case O_SIZE_32:   return result[((Frontend*)((char*)this - offsetof(Frontend, dword_rip_ptr)))->GetLabelID(label_name)];
                    case O_SIZE_64:   return result[((Frontend*)((char*)this - offsetof(Frontend, qword_rip_ptr)))->GetLabelID(label_name)];
                    case O_SIZE_128:  return result[((Frontend*)((char*)this - offsetof(Frontend, xmmword_rip_ptr)))->GetLabelID(label_name)];
                    case O_SIZE_256:  return result[((Frontend*)((char*)this - offsetof(Frontend, ymmword_rip_ptr)))->GetLabelID(label_name)];
                    }
                    return result;
                }
            };

            RipPtr<   Opd8 >	    byte_rip_ptr;
            RipPtr<  Opd16 >	    word_rip_ptr;
            RipPtr<  Opd32 >	    dword_rip_ptr;
            RipPtr<  Opd64 >	    qword_rip_ptr, rip_ptr;
            RipPtr< Opd128 >	    xmmword_rip_ptr;
            RipPtr< Opd256 >	    ymmword_rip_ptr;

            Frontend$CRTP()
                : jitasm::x86::Frontend$CRTP< Derived >(true),

                r8b(R8B),
                r9b(R9B),
                r10b(R10B),
                r11b(R11B),
                r12b(R12B),
                r13b(R13B),
                r14b(R14B),
                r15b(R15B),
                r8w(R8W),
                r9w(R9W),
                r10w(R10W),
                r11w(R11W),
                r12w(R12W),
                r13w(R13W),
                r14w(R14W),
                r15w(R15W),
                r8d(R8D),
                r9d(R9D),
                r10d(R10D),
                r11d(R11D),
                r12d(R12D),
                r13d(R13D),
                r14d(R14D),
                r15d(R15D),
                rax(RAX),
                rcx(RCX),
                rdx(RDX),
                rbx(RBX),
                rsp(RSP),
                rbp(RBP),
                rsi(RSI),
                rdi(RDI),
                r8(R8),
                r9(R9),
                r10(R10),
                r11(R11),
                r12(R12),
                r13(R13),
                r14(R14),
                r15(R15),
                xmm8(XMM8),
                xmm9(XMM9),
                xmm10(XMM10),
                xmm11(XMM11),
                xmm12(XMM12),
                xmm13(XMM13),
                xmm14(XMM14),
                xmm15(XMM15),
                ymm8(YMM8),
                ymm9(YMM9),
                ymm10(YMM10),
                ymm11(YMM11),
                ymm12(YMM12),
                ymm13(YMM13),
                ymm14(YMM14),
                ymm15(YMM15),
                zax(RAX),
                zcx(RCX),
                zdx(RDX),
                zbx(RBX),
                zsp(RSP),
                zbp(RBP),
                zsi(RSI),
                zdi(RDI)
            {
            }
            virtual ~Frontend$CRTP()
            {
            }
        };
    }
}
#endif // jitasm_Frontend_xx86_64_h__
