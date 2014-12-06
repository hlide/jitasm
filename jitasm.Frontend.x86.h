#pragma once
#ifndef jitasm_Frontend_x86_h__
#define jitasm_Frontend_x86_h__
#include "jitasm.x86.h"
#include "jitasm.Backend.x86.h"
#include "jitasm.Frontend.h"
namespace jitasm
{
    namespace x86
    {
        template < typename Derived > struct Frontend$CRTP : jitasm::Frontend$CRTP< Derived > /* using Curiously Recurring Template Pattern */
        {
            typedef jitasm::x86::Reg8	Reg8;
            typedef jitasm::x86::Reg16	Reg16;
            typedef jitasm::x86::Reg32	Reg32;
            typedef jitasm::x86::Reg64	Reg64;
            typedef jitasm::x86::MmxReg	MmxReg;
            typedef jitasm::x86::XmmReg	XmmReg;
            typedef jitasm::x86::YmmReg	YmmReg;
            typedef std::vector<Instr>	InstrList;

            Reg8					    al, cl, dl, bl, ah, ch, dh, bh;
            Reg16				        ax, cx, dx, bx, sp, bp, si, di;
            Reg32				        eax, ecx, edx, ebx, esp, ebp, esi, edi;
            FpuReg_st0			        st0;
            FpuReg				        st1, st2, st3, st4, st5, st6, st7;
            MmxReg				        mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7;
            XmmReg			        	xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
            YmmReg				        ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7;

            InstrList					instrs_;
            std::mutex	                codelock_;
            bool                        is64_;

            Frontend$CRTP(bool is64)
                : is64_(is64),

                al(AL),
                cl(CL),
                dl(DL),
                bl(BL),
                ah(AH),
                ch(CH),
                dh(DH),
                bh(BH),
                ax(AX),
                cx(CX),
                dx(DX),
                bx(BX),
                sp(SP),
                bp(BP),
                si(SI),
                di(DI),
                eax(EAX),
                ecx(ECX),
                edx(EDX),
                ebx(EBX),
                esp(ESP),
                ebp(EBP),
                esi(ESI),
                edi(EDI),
                st1(ST1),
                st2(ST2),
                st3(ST3),
                st4(ST4),
                st5(ST5),
                st6(ST6),
                st7(ST7),
                mm0(MM0),
                mm1(MM1),
                mm2(MM2),
                mm3(MM3),
                mm4(MM4),
                mm5(MM5),
                mm6(MM6),
                mm7(MM7),
                xmm0(XMM0),
                xmm1(XMM1),
                xmm2(XMM2),
                xmm3(XMM3),
                xmm4(XMM4),
                xmm5(XMM5),
                xmm6(XMM6),
                xmm7(XMM7),
                ymm0(YMM0),
                ymm1(YMM1),
                ymm2(YMM2),
                ymm3(YMM3),
                ymm4(YMM4),
                ymm5(YMM5),
                ymm6(YMM6),
                ymm7(YMM7)
            {
            }

            virtual ~Frontend$CRTP() {}

            void DeclareRegArg(detail::Opd const & var, detail::Opd const & arg, detail::Opd const & spill_slot = detail::Opd())
            {
                InstrList::iterator it = instrs_.begin();
                if (!instrs_.empty() && instrs_[0].GetID() == I_COMPILER_PROLOG) ++it;
                instrs_.insert(it, Instr(I_COMPILER_DECLARE_REG_ARG, 0, E_SPECIAL, Dummy(W(var), arg), spill_slot));
            }

            void DeclareStackArg(detail::Opd const & var, detail::Opd const & arg)
            {
                InstrList::iterator it = instrs_.begin();
                if (!instrs_.empty() && instrs_[0].GetID() == I_COMPILER_PROLOG) ++it;
                instrs_.insert(it, Instr(I_COMPILER_DECLARE_STACK_ARG, 0, E_SPECIAL, W(var), R(arg)));
            }

            void DeclareResultReg(detail::Opd const & var)
            {
                if (var.IsGpReg())
                {
                    AppendSpecial(I_COMPILER_DECLARE_RESULT_REG, 0, Dummy(R(var), is64_ ? detail::Opd(rax) : detail::Opd(eax)));
                }
                else if (var.IsMmxReg())
                {
                    AppendSpecial(I_COMPILER_DECLARE_RESULT_REG, 0, Dummy(R(var), mm0));
                }
                else if (var.IsXmmReg())
                {
                    AppendSpecial(I_COMPILER_DECLARE_RESULT_REG, 0, Dummy(R(var), xmm0));
                }
            }

            void Prolog()
            {
                AppendSpecial(I_COMPILER_PROLOG, 0);
            }

            void Epilog()
            {
                AppendSpecial(I_COMPILER_EPILOG, 0);
            }

            static void ChangeLabelID(Instr & instr, size_t label_id)
            {
                instr.GetOpd(0).imm_ = label_id;
            }

            static bool IsJump(InstrID id)
            {
                return id == I_JMP || id == I_JCC || id == I_LOOPCC;
            }

            static bool HasRIP(detail::Opd const & opd)
            {
                return opd.IsMem() && (opd.GetBase().type == R_TYPE_IP);
            }

            size_t GetJumpTo(Instr const & instr) const
            {
                size_t label_id = (size_t)instr.GetOpd(0).GetImm();
                return label_id != size_t(-1) ? labels_[label_id].instr : 0;
            }

            void ResolveJumpAndRIP()
            {
                // translate label keys into instruction indices
                for (auto & instr : instrs_)
                {
                    if (IsJump(instr.GetID()))
                    {
                        size_t target = GetJumpTo(instr);
                        instr.GetOpd(1) = Imm64(target);	// instruction number
                        instr.GetOpd(0) = Imm8(0x7F);       // short jump instruction
                    }
                    else if (HasRIP(instr.GetOpd(1)))
                    {
                        size_t label_id = (size_t)instr.GetOpd(1).GetDisp();
                        instr.GetOpd(1).disp_ = sint64(labels_[label_id].instr);	// instruction number
                    }
                }

                // choose short jump instruction when possible
                std::vector< int > offsets;
                offsets.reserve(instrs_.size() + 1);
                bool retry;
                do
                {
                    offsets.clear();
                    offsets.push_back(0);
                    Backend pre(is64_);
                    for (auto & instr : instrs_)
                    {
                        pre.Assemble(instr);
                        offsets.push_back((int)pre.GetSize());
                    }

                    retry = false;
                    size_t i = 0;
                    for (auto & instr : instrs_)
                    {
                        if (IsJump(instr.GetID()))
                        {
                            size_t d = (size_t)instr.GetOpd(1).GetImm();
                            int rel = (int)offsets[d] - offsets[i + 1];
                            if ((instr.GetID() == I_JMP || instr.GetID() == I_JCC) && !rel) // eat JMP +0
                            {
                                instr = Instr(I_NULL, 0, 0);
                                retry = true;
                                break;
                            }
                            OpdSize size = instr.GetOpd(0).GetSize();
                            if (size == O_SIZE_8)
                            {
                                if (!detail::IsInt8(rel)) // choose near jump instruction 
                                {
                                    instr.GetOpd(0) = Imm32(0x7FFFFFFF);

                                    retry = true;
                                    break;
                                }
                            }
                            if (size_t(d - 1) < instrs_.size())
                            {
                                auto & target = instrs_[d - 1];
                                if (target.GetID() == I_ALIGN && target.GetOpd(0).GetImm() == 0)
                                {
                                    target.GetOpd(0) = Imm8(4);
                                    retry = true;
                                    break;
                                }
                            }
                        }
                        ++i;
                    }
                }
                while (retry);

                // resolve jumps and rip reference
                size_t i = 0;
                for (auto & instr : instrs_)
                {
                    if (IsJump(instr.GetID()))
                    {
                        size_t d = (size_t)instr.GetOpd(1).GetImm();
                        int rel = (int)offsets[d] - offsets[i + 1];
                        OpdSize size = instr.GetOpd(0).GetSize();
                        if (size == O_SIZE_8)
                        {
                            instr.GetOpd(0) = Imm8((uint8)rel);
                        }
                        else if (size == O_SIZE_32)
                        {
                            instr.GetOpd(0) = Imm32((uint32)rel);
                            instr.GetOpd(1) = detail::Opd();
                        }
                    }
                    else if (HasRIP(instr.GetOpd(1)))
                    {
                        size_t d = (size_t)instr.GetOpd(1).GetDisp();
                        int rel = (int)offsets[d] - offsets[i + 1];
                        instr.GetOpd(1).disp_ = sint64(rel);
                    }
                    ++i;
                }
            }

            void Assemble()
            {
                std::lock_guard< std::mutex > guard(codelock_);

                if (assembled_) return;

                instrs_.clear();
                labels_.clear();
                instrs_.reserve(128);

                derived().InternalMain();

                //compiler::Compile(*this);

                if (!labels_.empty())
                {
                    ResolveJumpAndRIP();
                }

                Backend pre(is64_);
                for (auto & instr : instrs_)
                {
                    pre.Assemble(instr);
                }

                size_t codesize = pre.GetSize();

                derived().ResetBuffer(codesize);

                Backend backend(is64_, derived().GetBufferPointer(), derived().GetCodeSize());
                for (auto & instr : instrs_)
                {
                    backend.Assemble(instr);
                }

                InstrList().swap(instrs_);
                LabelList().swap(labels_);

                assembled_ = true;
            }

            void AppendInstr(InstrID id, detail::Opd const & opd1 = detail::Opd(), detail::Opd const & opd2 = detail::Opd(), detail::Opd const & opd3 = detail::Opd(), detail::Opd const & opd4 = detail::Opd(), detail::Opd const & opd5 = detail::Opd(), detail::Opd const & opd6 = detail::Opd())
            {
                instrs_.push_back(Instr(id, opd1, opd2, opd3, opd4, opd5, opd6));
            }

            //void AppendInstr(InstrID id, uint32 opcode, uint32 encoding_flag, detail::Opd const & opd1 = detail::Opd(), detail::Opd const & opd2 = detail::Opd(), detail::Opd const & opd3 = detail::Opd(), detail::Opd const & opd4 = detail::Opd(), detail::Opd const & opd5 = detail::Opd(), detail::Opd const & opd6 = detail::Opd())
            //{
            //	instrs_.push_back(Instr(id, opcode, encoding_flag, opd1, opd2, opd3, opd4, opd5, opd6));
            //}

            void AppendSpecial(InstrID id, uint32 opcode, detail::Opd const & opd1 = detail::Opd(), detail::Opd const & opd2 = detail::Opd(), detail::Opd const & opd3 = detail::Opd(), detail::Opd const & opd4 = detail::Opd(), detail::Opd const & opd5 = detail::Opd(), detail::Opd const & opd6 = detail::Opd())
            {
                instrs_.push_back(Instr(id, opcode, E_SPECIAL, opd1, opd2, opd3, opd4, opd5, opd6));
            }

            void AppendJmp(size_t label_id)
            {
                AppendSpecial(I_JMP, 0, Imm64(label_id));
            }

            void AppendJcc(JumpCondition jcc, size_t label_id)
            {
                AppendSpecial(I_JCC, jcc, Imm64(label_id));
            }

            void align(Imm8 const & imm = 4)
            {
                AppendSpecial(I_ALIGN, 0, imm);
            }

            void source(uint64 source_key)
            {
                AppendSpecial(I_SOURCE, 0, Imm64(source_key));
            }

            void db(const Imm8& imm)
            {
                AppendSpecial(I_DB, 0, imm);
            }

            void dw(const Imm16& imm)
            {
                AppendSpecial(I_DW, 0, imm);
            }

            void dd(const Imm32& imm)
            {
                AppendSpecial(I_DD, 0, imm);
            }

            void dq(const Imm64& imm)
            {
                AppendSpecial(I_DQ, 0, imm);
            }
        };
    }
}
#endif // jitasm_Frontend_x86_h__