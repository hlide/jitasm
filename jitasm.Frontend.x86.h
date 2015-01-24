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

            virtual ~Frontend$CRTP()
            {
            }

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
                return id == I_JMP || id == I_JCC;
            }

            static bool HasRIP(detail::Opd const & opd)
            {
                return opd.IsMem() && (opd.GetBase().type == R_TYPE_IP);
            }

            size_t GetJumpTo(Instr const & instr) const
            {
                auto label_id = size_t(instr.GetOpd(0).GetImm());
                return label_id != size_t(-1) ? labels_[label_id].instr : 0;
            }

            void ResolveJumpAndRIP()
            {
                // translate label keys into instruction indices
                for (auto & instr : instrs_)
                {
                    if (IsJump(instr.GetID()))
                    {
                        auto target = GetJumpTo(instr);
                        instr.GetOpd(1) = Imm64(target);	// instruction number
                        instr.GetOpd(0) = Imm8(0x7F);       // short jump instruction
                    }
                    else if (HasRIP(instr.GetOpd(1)))
                    {
                        auto label_id = size_t(instr.GetOpd(1).GetDisp());
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
                            auto d = size_t(instr.GetOpd(1).GetImm());
                            auto r = int(offsets[d] - offsets[i + 1]);
                            
                            if ((instr.GetID() == I_JMP || instr.GetID() == I_JCC) && !r) // eat JMP +0
                            {
                                instr = Instr(I_NULL, 0, 0);
                                retry = true;
                                break;
                            }
                            
                            auto s = instr.GetOpd(0).GetSize();
                            
                            if (s == O_SIZE_8)
                            {
                                if (!detail::IsInt8(r)) // choose near jump instruction 
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
                        auto d = size_t(instr.GetOpd(1).GetImm());
                        auto r = int(offsets[d] - offsets[i + 1]);
                        auto s = instr.GetOpd(0).GetSize();

                        /**/ if (s == O_SIZE_8)
                        {
                            instr.GetOpd(0) = Imm8(uint8(r));
                        }
                        else if (s == O_SIZE_32)
                        {
                            instr.GetOpd(0) = Imm32(uint32(r));
                            instr.GetOpd(1) = detail::Opd();
                        }
                    }
                    else if (HasRIP(instr.GetOpd(1)))
                    {
                        auto d = size_t(instr.GetOpd(1).GetDisp());
                        auto r = int(offsets[d] - offsets[i + 1]);

                        instr.GetOpd(1).disp_ = sint64(r);
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

#ifdef JITASM_TEST
            void Test(InstrID id)
            {
                std::lock_guard< std::mutex > guard(codelock_);

                instrs_.clear();
                labels_.clear();
                instrs_.reserve(128);

                Backend pre(is64_);

                pre.TestInstr(id, instrs_, is64_);

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
#endif

            void AppendInstr(InstrID id, detail::Opd const & opd1 = detail::Opd(), detail::Opd const & opd2 = detail::Opd(), detail::Opd const & opd3 = detail::Opd(), detail::Opd const & opd4 = detail::Opd(), detail::Opd const & opd5 = detail::Opd(), detail::Opd const & opd6 = detail::Opd())
            {
                instrs_.push_back(Instr(id, opd1, opd2, opd3, opd4, opd5, opd6));
            }

            void AppendCondInstr(InstrID id, ConditionCode cc, detail::Opd const & opd1 = detail::Opd(), detail::Opd const & opd2 = detail::Opd(), detail::Opd const & opd3 = detail::Opd(), detail::Opd const & opd4 = detail::Opd(), detail::Opd const & opd5 = detail::Opd(), detail::Opd const & opd6 = detail::Opd())
            {
                instrs_.push_back(Instr(id, uint32(cc), 0, opd1, opd2, opd3, opd4, opd5, opd6));
            }

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

            void db(Imm8 const & imm)
            {
                AppendSpecial(I_DB, 0, imm);
            }

            void dw(Imm16 const & imm)
            {
                AppendSpecial(I_DW, 0, imm);
            }

            void dd(Imm32 const & imm)
            {
                AppendSpecial(I_DD, 0, imm);
            }

            void dq(Imm64 const & imm)
            {
                AppendSpecial(I_DQ, 0, imm);
            }

            /////////////

            void adc(Reg8 const & a1, Imm8 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Mem8 const & a1, Imm8 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg8 const & a1, Reg8 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg8 const & a1, Mem8 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Mem8 const & a1, Reg8 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg16 const & a1, Imm16 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Mem16 const & a1, Imm16 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg16 const & a1, Mem16 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg32 const & a1, Imm32 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Mem32 const & a1, Imm32 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Reg32 const & a1, Mem32 const & a2) { AppendInstr(I_ADC, a1, a2); }
            void adc(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_ADC, a1, a2); }

            void add(Reg8 const & a1, Imm8 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Mem8 const & a1, Imm8 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg8 const & a1, Reg8 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg8 const & a1, Mem8 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Mem8 const & a1, Reg8 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg16 const & a1, Imm16 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Mem16 const & a1, Imm16 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg16 const & a1, Mem16 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg32 const & a1, Imm32 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Mem32 const & a1, Imm32 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Reg32 const & a1, Mem32 const & a2) { AppendInstr(I_ADD, a1, a2); }
            void add(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_ADD, a1, a2); }

            void and(Reg8 const & a1, Imm8 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Mem8 const & a1, Imm8 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg8 const & a1, Reg8 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg8 const & a1, Mem8 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Mem8 const & a1, Reg8 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg16 const & a1, Imm16 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Mem16 const & a1, Imm16 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg16 const & a1, Mem16 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg32 const & a1, Imm32 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Mem32 const & a1, Imm32 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Reg32 const & a1, Mem32 const & a2) { AppendInstr(I_AND, a1, a2); }
            void and(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_AND, a1, a2); }

            void bsf(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_BSF, a1, a2); }
            void bsf(Reg16 const & a1, Mem16 const & a2) { AppendInstr(I_BSF, a1, a2); }
            void bsf(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_BSF, a1, a2); }
            void bsf(Reg32 const & a1, Mem32 const & a2) { AppendInstr(I_BSF, a1, a2); }

            void bsr(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_BSR, a1, a2); }
            void bsr(Reg16 const & a1, Mem16 const & a2) { AppendInstr(I_BSR, a1, a2); }
            void bsr(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_BSR, a1, a2); }
            void bsr(Reg32 const & a1, Mem32 const & a2) { AppendInstr(I_BSR, a1, a2); }

            void bswap(Reg32 const & a1) { AppendInstr(I_BSWAP, a1); }

            void bt(Reg16 const & a1, Imm8 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Mem16 const & a1, Imm8 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Reg32 const & a1, Imm8 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Mem32 const & a1, Imm8 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_BT, a1, a2); }
            void bt(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_BT, a1, a2); }

            void btc(Reg16 const & a1, Imm8 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Mem16 const & a1, Imm8 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Reg32 const & a1, Imm8 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Mem32 const & a1, Imm8 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_BTC, a1, a2); }
            void btc(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_BTC, a1, a2); }

            void btr(Reg16 const & a1, Imm8 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Mem16 const & a1, Imm8 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Reg32 const & a1, Imm8 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Mem32 const & a1, Imm8 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_BTR, a1, a2); }
            void btr(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_BTR, a1, a2); }

            void bts(Reg16 const & a1, Imm8 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Mem16 const & a1, Imm8 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Reg32 const & a1, Imm8 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Mem32 const & a1, Imm8 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_BTS, a1, a2); }
            void bts(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_BTS, a1, a2); }

            void cbw() { AppendInstr(I_CBW); }
            
            void cdq() { AppendInstr(I_CDQ); }

            void clc() { AppendInstr(I_CLC); }

            void cld() { AppendInstr(I_CLD); }

            void clflush(Mem8 const & a1) { AppendInstr(I_CLFLUSH, a1);  }

            void cli() { AppendInstr(I_CLI); }
            
            void clts() { AppendInstr(I_CLTS); }

            void cmc() { AppendInstr(I_CMC); }

            void cmovcc(ConditionCode cc, Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, cc, a1, a2); }
            void cmovcc(ConditionCode cc, Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, cc, a1, a2); }
            void cmovcc(ConditionCode cc, Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, cc, a1, a2); }
            void cmovcc(ConditionCode cc, Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, cc, a1, a2); }
            void cmovo(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_O, a1, a2); }
            void cmovo(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_O, a1, a2); }
            void cmovo(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_O, a1, a2); }
            void cmovo(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_O, a1, a2); }
            void cmovno(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NO, a1, a2); }
            void cmovno(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NO, a1, a2); }
            void cmovno(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NO, a1, a2); }
            void cmovno(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NO, a1, a2); }
            void cmovb(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_B, a1, a2); }
            void cmovb(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_B, a1, a2); }
            void cmovb(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_B, a1, a2); }
            void cmovb(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_B, a1, a2); }
            void cmovc(Reg16 const & a1, Reg16 const & a2) { cmovb(a1, a2); }
            void cmovc(Reg16 const & a1, Mem16 const & a2) { cmovb(a1, a2); }
            void cmovc(Reg32 const & a1, Reg32 const & a2) { cmovb(a1, a2); }
            void cmovc(Reg32 const & a1, Mem32 const & a2) { cmovb(a1, a2); }
            void cmovnae(Reg16 const & a1, Reg16 const & a2) { cmovb(a1, a2); }
            void cmovnae(Reg16 const & a1, Mem16 const & a2) { cmovb(a1, a2); }
            void cmovnae(Reg32 const & a1, Reg32 const & a2) { cmovb(a1, a2); }
            void cmovnae(Reg32 const & a1, Mem32 const & a2) { cmovb(a1, a2); }
            void cmovae(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_AE, a1, a2); }
            void cmovae(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_AE, a1, a2); }
            void cmovae(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_AE, a1, a2); }
            void cmovae(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_AE, a1, a2); }
            void cmovnb(Reg16 const & a1, Reg16 const & a2) { cmovae(a1, a2); }
            void cmovnb(Reg16 const & a1, Mem16 const & a2) { cmovae(a1, a2); }
            void cmovnb(Reg32 const & a1, Reg32 const & a2) { cmovae(a1, a2); }
            void cmovnb(Reg32 const & a1, Mem32 const & a2) { cmovae(a1, a2); }
            void cmovnc(Reg16 const & a1, Reg16 const & a2) { cmovae(a1, a2); }
            void cmovnc(Reg16 const & a1, Mem16 const & a2) { cmovae(a1, a2); }
            void cmovnc(Reg32 const & a1, Reg32 const & a2) { cmovae(a1, a2); }
            void cmovnc(Reg32 const & a1, Mem32 const & a2) { cmovae(a1, a2); }
            void cmove(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_E, a1, a2); }
            void cmove(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_E, a1, a2); }
            void cmove(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_E, a1, a2); }
            void cmove(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_E, a1, a2); }
            void cmovz(Reg16 const & a1, Reg16 const & a2) { cmove(a1, a2); }
            void cmovz(Reg16 const & a1, Mem16 const & a2) { cmove(a1, a2); }
            void cmovz(Reg32 const & a1, Reg32 const & a2) { cmove(a1, a2); }
            void cmovz(Reg32 const & a1, Mem32 const & a2) { cmove(a1, a2); }
            void cmovne(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NE, a1, a2); }
            void cmovne(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NE, a1, a2); }
            void cmovne(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NE, a1, a2); }
            void cmovne(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NE, a1, a2); }
            void cmovnz(Reg16 const & a1, Reg16 const & a2) { cmovne(a1, a2); }
            void cmovnz(Reg16 const & a1, Mem16 const & a2) { cmovne(a1, a2); }
            void cmovnz(Reg32 const & a1, Reg32 const & a2) { cmovne(a1, a2); }
            void cmovnz(Reg32 const & a1, Mem32 const & a2) { cmovne(a1, a2); }
            void cmovbe(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_BE, a1, a2); }
            void cmovbe(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_BE, a1, a2); }
            void cmovbe(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_BE, a1, a2); }
            void cmovbe(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_BE, a1, a2); }
            void cmovna(Reg16 const & a1, Reg16 const & a2) { cmovbe(a1, a2); }
            void cmovna(Reg16 const & a1, Mem16 const & a2) { cmovbe(a1, a2); }
            void cmovna(Reg32 const & a1, Reg32 const & a2) { cmovbe(a1, a2); }
            void cmovna(Reg32 const & a1, Mem32 const & a2) { cmovbe(a1, a2); }
            void cmova(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_A, a1, a2); }
            void cmova(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_A, a1, a2); }
            void cmova(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_A, a1, a2); }
            void cmova(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_A, a1, a2); }
            void cmovnbe(Reg16 const & a1, Reg16 const & a2) { cmova(a1, a2); }
            void cmovnbe(Reg16 const & a1, Mem16 const & a2) { cmova(a1, a2); }
            void cmovnbe(Reg32 const & a1, Reg32 const & a2) { cmova(a1, a2); }
            void cmovnbe(Reg32 const & a1, Mem32 const & a2) { cmova(a1, a2); }
            void cmovs(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_S, a1, a2); }
            void cmovs(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_S, a1, a2); }
            void cmovs(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_S, a1, a2); }
            void cmovs(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_S, a1, a2); }
            void cmovns(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NS, a1, a2); }
            void cmovns(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NS, a1, a2); }
            void cmovns(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NS, a1, a2); }
            void cmovns(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NS, a1, a2); }
            void cmovp(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_P, a1, a2); }
            void cmovp(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_P, a1, a2); }
            void cmovp(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_P, a1, a2); }
            void cmovp(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_P, a1, a2); }
            void cmovnpe(Reg16 const & a1, Reg16 const & a2) { cmovp(a1, a2); }
            void cmovnpe(Reg16 const & a1, Mem16 const & a2) { cmovp(a1, a2); }
            void cmovnpe(Reg32 const & a1, Reg32 const & a2) { cmovp(a1, a2); }
            void cmovnpe(Reg32 const & a1, Mem32 const & a2) { cmovp(a1, a2); }
            void cmovnp(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NP, a1, a2); }
            void cmovnp(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_NP, a1, a2); }
            void cmovnp(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NP, a1, a2); }
            void cmovnp(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_NP, a1, a2); }
            void cmovnpo(Reg16 const & a1, Reg16 const & a2) { cmovnp(a1, a2); }
            void cmovnpo(Reg16 const & a1, Mem16 const & a2) { cmovnp(a1, a2); }
            void cmovnpo(Reg32 const & a1, Reg32 const & a2) { cmovnp(a1, a2); }
            void cmovnpo(Reg32 const & a1, Mem32 const & a2) { cmovnp(a1, a2); }
            void cmovge(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_GE, a1, a2); }
            void cmovge(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_GE, a1, a2); }
            void cmovge(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_GE, a1, a2); }
            void cmovge(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_GE, a1, a2); }
            void cmovnl(Reg16 const & a1, Reg16 const & a2) { cmovge(a1, a2); }
            void cmovnl(Reg16 const & a1, Mem16 const & a2) { cmovge(a1, a2); }
            void cmovnl(Reg32 const & a1, Reg32 const & a2) { cmovge(a1, a2); }
            void cmovnl(Reg32 const & a1, Mem32 const & a2) { cmovge(a1, a2); }
            void cmovle(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_LE, a1, a2); }
            void cmovle(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_LE, a1, a2); }
            void cmovle(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_LE, a1, a2); }
            void cmovle(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_LE, a1, a2); }
            void cmovng(Reg16 const & a1, Reg16 const & a2) { cmovle(a1, a2); }
            void cmovng(Reg16 const & a1, Mem16 const & a2) { cmovle(a1, a2); }
            void cmovng(Reg32 const & a1, Reg32 const & a2) { cmovle(a1, a2); }
            void cmovng(Reg32 const & a1, Mem32 const & a2) { cmovle(a1, a2); }
            void cmovg(Reg16 const & a1, Reg16 const & a2) { AppendCondInstr(I_CMOVCC, CC_G, a1, a2); }
            void cmovg(Reg16 const & a1, Mem16 const & a2) { AppendCondInstr(I_CMOVCC, CC_G, a1, a2); }
            void cmovg(Reg32 const & a1, Reg32 const & a2) { AppendCondInstr(I_CMOVCC, CC_G, a1, a2); }
            void cmovg(Reg32 const & a1, Mem32 const & a2) { AppendCondInstr(I_CMOVCC, CC_G, a1, a2); }
            void cmovnle(Reg16 const & a1, Reg16 const & a2) { cmovg(a1, a2); }
            void cmovnle(Reg16 const & a1, Mem16 const & a2) { cmovg(a1, a2); }
            void cmovnle(Reg32 const & a1, Reg32 const & a2) { cmovg(a1, a2); }
            void cmovnle(Reg32 const & a1, Mem32 const & a2) { cmovg(a1, a2); }

            void cmp(Reg8 const & a1, Imm8 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Mem8 const & a1, Imm8 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg8 const & a1, Reg8 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg8 const & a1, Mem8 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Mem8 const & a1, Reg8 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg16 const & a1, Imm16 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Mem16 const & a1, Imm16 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg16 const & a1, Reg16 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg16 const & a1, Mem16 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Mem16 const & a1, Reg16 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg32 const & a1, Imm32 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Mem32 const & a1, Imm32 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg32 const & a1, Reg32 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Reg32 const & a1, Mem32 const & a2) { AppendInstr(I_CMP, a1, a2); }
            void cmp(Mem32 const & a1, Reg32 const & a2) { AppendInstr(I_CMP, a1, a2); }

            void cwd() { AppendInstr(I_CWD); }

            void cwde() { AppendInstr(I_CWDE); }

        };
    }
}
#endif // jitasm_Frontend_x86_h__