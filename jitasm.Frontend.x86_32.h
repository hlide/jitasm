#pragma once
#ifndef jitasm_Frontend_x86_32_h__
#define jitasm_Frontend_x86_32_h__
#include "jitasm.x86.h"
#include "jitasm.x86_32.h"
#include "jitasm.Frontend.x86.h"
namespace jitasm
{
	namespace x86_32
	{
		using namespace jitasm::x86;

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
			typedef jitasm::x86::Addr32 Addr;
			typedef jitasm::x86::Reg32	Reg;

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

			Reg					        zax, zcx, zdx, zbx, zsp, zbp, zsi, zdi;
			AddressingPtr<Opd32>		ptr;

			detail::StackManager	    stack_manager_;

            Frontend$CRTP()
                : jitasm::x86::Frontend$CRTP< Derived >(false),

                zax(EAX),
                zcx(ECX),
                zdx(EDX),
                zbx(EBX),
                zsp(ESP),
                zbp(EBP),
                zsi(ESI),
                zdi(EDI)
            {
            }
			virtual ~Frontend$CRTP()
            {
            }
		};
	}
}
#endif // jitasm_Frontend_x86_32_h__