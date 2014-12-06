#include "jitasm.Backend.x86.h"

namespace jitasm
{
	namespace x86
	{
		void Backend::EncodeInstr(Instr & instr)
		{
			uint32  sub_opcode = 0;
			switch (instr.id_)
			{
			case I_ADC: sub_opcode = 2; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_ADD: sub_opcode = 0; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_AND: sub_opcode = 4; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_CMP: sub_opcode = 7; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_OR:  sub_opcode = 1; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_SBB: sub_opcode = 3; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_SUB: sub_opcode = 5; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			case I_XOR: sub_opcode = 6; goto I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR;
			I_ADC_ADD_AND_CMP_OR_SBB_SUB_XOR:
			{
				auto opd1 = instr.opd_[0];
				auto opd2 = instr.opd_[1];
				bool has_imm = opd2.IsImm();
				if (has_imm)
				{
                    instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                    if (opd1.GetReg().id == EAX && (opd1.GetSize() == O_SIZE_8 || !detail::IsInt8(opd2.GetImm())))
					{
						instr.opcode_ = (sub_opcode * 8) + (O_SIZE_8 == opd1.GetSize() ? 4 : 5);
						instr.opd_[0] = instr.id_ == I_CMP ? R(opd1) : RW(opd1);
						instr.opd_[1] = opd2;
                    }
					else
					{
						instr.opcode_ = (O_SIZE_8 == opd1.GetSize() ? 0x80 : (detail::IsInt8(opd2.GetImm()) ? 0x83 : 0x81));
						instr.opd_[0] = Imm8(sub_opcode);
						instr.opd_[1] = instr.id_ == I_CMP ? R(opd1) : RW(opd1);
						instr.opd_[2] = opd2;
					}
				}
				else if (opd1.IsGpReg())
				{
                    instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                    instr.opcode_ = (sub_opcode * 8) + (O_SIZE_8 == opd1.GetSize() ? 0x02 : 0x03);
					instr.opd_[0] = instr.id_ == I_CMP ? R(opd1) : RW(opd1);
					instr.opd_[1] = R(opd2);
				}
                else if (opd2.IsGpReg())
				{
                    instr.encoding_flag_ = opd2.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd2.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                    instr.opcode_ = (sub_opcode * 8) + (O_SIZE_8 == opd1.GetSize() ? 0x00 : 0x01);
					instr.opd_[0] = R(opd2);
					instr.opd_[1] = instr.id_ == I_CMP ? R(opd1) : RW(opd1);
				}
				break;
			}
			case I_BSF: instr.opcode_ = 0x0FBC; goto I_BSF_BSR;
			case I_BSR: instr.opcode_ = 0x0FBD; goto I_BSF_BSR;
			I_BSF_BSR:
			{
				auto opd1 = instr.opd_[0];
				auto opd2 = instr.opd_[1];
				instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
				instr.opd_[0] = W(opd1);
				instr.opd_[1] = R(opd2);
				break;
			}
			case I_BSWAP:
			{
				auto opd1 = instr.opd_[0];
				instr.opcode_ = 0x0FBC;
				instr.encoding_flag_ = opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
				instr.opd_[0] = RW(opd1);
				break;
			}
			case I_BT:  sub_opcode = 4; goto I_BT_BTC_BTR_BTS;
			case I_BTC: sub_opcode = 7; goto I_BT_BTC_BTR_BTS;
			case I_BTR: sub_opcode = 6; goto I_BT_BTC_BTR_BTS;
			case I_BTS: sub_opcode = 5; goto I_BT_BTC_BTR_BTS;
			I_BT_BTC_BTR_BTS:
			{
				auto opd1 = instr.opd_[0];
				auto opd2 = instr.opd_[1];
				bool has_imm = opd2.IsImm();
				if (has_imm)
				{
					instr.opcode_ = 0x0FBA;
					instr.opd_[0] = Imm8(sub_opcode);
					instr.opd_[1] = instr.id_ == I_BT ? R(opd1) : RW(opd1);
					instr.opd_[2] = opd2;
				}
				else
				{
					instr.opcode_ = 0x0F83 + sub_opcode * 8;
					instr.opd_[0] = R(opd2);
					instr.opd_[1] = instr.id_ == I_BT ? R(opd1) : RW(opd1);
				}
				instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
				break;
			}
			case I_CALL:
			{
				auto opd1 = instr.opd_[0];
				instr.encoding_flag_ = (instr.encoding_flag_ & E_NO_BREAK) | E_ENCODED;
				instr.opcode_ = 0xFF;
				instr.opd_[0] = Imm8(2);
				instr.opd_[1] = R(opd1);
				break;
			}
			case I_CBW:  sub_opcode = 0x98; instr.encoding_flag_ = (E_OPERAND_SIZE_PREFIX | E_ENCODED); goto I_CBW_CWDE_CDQE_CWD_CDQ_CQO;
			case I_CWDE: sub_opcode = 0x98; instr.encoding_flag_ = E_ENCODED;                           goto I_CBW_CWDE_CDQE_CWD_CDQ_CQO;
			case I_CDQE: sub_opcode = 0x98; instr.encoding_flag_ = (E_REXW_PREFIX | E_ENCODED);         goto I_CBW_CWDE_CDQE_CWD_CDQ_CQO;
			case I_CWD:  sub_opcode = 0x99; instr.encoding_flag_ = (E_OPERAND_SIZE_PREFIX | E_ENCODED); goto I_CBW_CWDE_CDQE_CWD_CDQ_CQO;
			case I_CDQ:	 sub_opcode = 0x99; instr.encoding_flag_ = E_ENCODED;                           goto I_CBW_CWDE_CDQE_CWD_CDQ_CQO;
			case I_CQO:	 sub_opcode = 0x99; instr.encoding_flag_ = (E_REXW_PREFIX | E_ENCODED);         goto I_CBW_CWDE_CDQE_CWD_CDQ_CQO;
			I_CBW_CWDE_CDQE_CWD_CDQ_CQO:
			{
				instr.opcode_ = sub_opcode;
				instr.opd_[0] = detail::Dummy(RW(Reg64(RAX)));
				break;
			}
			case I_CLC:  sub_opcode = 0x00F8; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_CLD:  sub_opcode = 0x00FC; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_CLI:  sub_opcode = 0x00FA; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_CLTS: sub_opcode = 0x0F06; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_CMC:  sub_opcode = 0x00F5; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_STC:  sub_opcode = 0x00F9; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_STD:  sub_opcode = 0x00FD; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			case I_STI:  sub_opcode = 0x00FB; goto I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI;
			I_CLC_CLD_CLI_CLTS_CMC_STC_STD_STI :
			{
				instr.encoding_flag_ = E_ENCODED;
				instr.opcode_ = sub_opcode;
				break;
			}
			case I_CMOVCC:
			{
				auto opd1 = instr.opd_[0];
				auto opd2 = instr.opd_[1];
				instr.opcode_ = 0x0F40 + (instr.opcode_ & 15);
				instr.opd_[0] = RW(opd1);
				instr.opd_[1] = R(opd2);
				instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
				break;
			}
			case I_CMPS_B:  sub_opcode = 0xA6; instr.encoding_flag_ = E_ENCODED;                           goto I_CMPS_BWDQ;
			case I_CMPS_W:  sub_opcode = 0xA7; instr.encoding_flag_ = (E_OPERAND_SIZE_PREFIX | E_ENCODED); goto I_CMPS_BWDQ;
			case I_CMPS_D:  sub_opcode = 0xA7; instr.encoding_flag_ = E_ENCODED;                           goto I_CMPS_BWDQ;
			case I_CMPS_Q:  sub_opcode = 0xA7; instr.encoding_flag_ = (E_REXW_PREFIX | E_ENCODED);         goto I_CMPS_BWDQ;
			I_CMPS_BWDQ:
			{
				instr.opd_[0] = detail::Dummy(RW(Reg64(RDI)));
				instr.opd_[1] = detail::Dummy(RW(Reg64(RSI)));
				break;
			}
			case I_CMPXCHG:
			{
				auto opd1 = instr.opd_[0];
				auto opd2 = instr.opd_[1];
				auto opd3 = instr.opd_[2];
				instr.opcode_ = opd1.GetSize() == O_SIZE_8 ? 0x0FB0 : 0x0FB1;
				instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
				instr.opd_[0] = R(opd2);
				instr.opd_[1] = RW(opd1);
				instr.opd_[2] = detail::Dummy(RW(opd3), Reg64(RAX));
				break;
			}
			case I_CMPXCHG8B:  instr.encoding_flag_ = E_ENCODED;                   goto I_CMPXCHG8B_CMPXCHG16B;
			case I_CMPXCHG16B: instr.encoding_flag_ = (E_REXW_PREFIX | E_ENCODED); goto I_CMPXCHG8B_CMPXCHG16B;
			I_CMPXCHG8B_CMPXCHG16B:
			{
				auto opd1 = instr.opd_[0];
				instr.opcode_ = 0x0FC7;
				instr.opd_[0] = Imm8(1);
				instr.opd_[1] = RW(opd1);
				instr.opd_[2] = detail::Dummy(RW(Reg64(RDX)));
				instr.opd_[3] = detail::Dummy(RW(Reg64(RAX)));
				instr.opd_[4] = detail::Dummy(R(Reg64(RCX)));
				instr.opd_[5] = detail::Dummy(R(Reg64(RBX)));
				break;
			}
			case I_CPUID:
			{
				instr.opcode_ = 0x0FA2;
				instr.encoding_flag_ = E_ENCODED;
				instr.opd_[0] = detail::Dummy(RW(Reg64(RAX)));
				instr.opd_[1] = detail::Dummy(RW(Reg64(RDX)));
				instr.opd_[2] = detail::Dummy(RW(Reg64(RAX)));
				instr.opd_[3] = detail::Dummy(R(Reg64(RCX)));
				break;
			}
			case I_DEC: sub_opcode = 1; goto I_DEC_INC;
			case I_INC: sub_opcode = 0; goto I_DEC_INC;
			I_DEC_INC:
			{
				auto opd1 = instr.opd_[0];
				if (opd1.GetSize() == O_SIZE_8)
				{
					instr.opcode_ = 0xFE;
					instr.encoding_flag_ = E_ENCODED;
					instr.opd_[0] = Imm8(sub_opcode);
					instr.opd_[1] = RW(opd1);
				}
				else if (!is64_ && opd1.IsReg())
				{
					instr.opcode_ = 0x40 + 8 * sub_opcode;
					instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : E_ENCODED;
					instr.opd_[0] = RW(opd1);
				}
				else
				{
					instr.opcode_ = 0xFF;
					instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
					instr.opd_[0] = Imm8(sub_opcode);
					instr.opd_[1] = RW(opd1);
				}
				break;
			}
			case I_DIV:
				break; 
			case I_ENTER:
				break;
			case I_HLT:
				break;
			case I_IDIV:
				break;
			case I_IMUL:
				break;
			case I_IN:
				break;
			case I_INS_B:
				break;
			case I_INS_W:
				break;
			case I_INS_D:
				break;
			case I_INVD:
				break;
			case I_INVLPG:
				break;
			case I_INT3:
				break;
			case I_INTN:
				break;
			case I_INTO:
				break;
			case I_IRET:
				break;
			case I_IRETD:
				break;
			case I_IRETQ:
				break;
			case I_JMP:
            {
                auto opd1 = instr.opd_[0];
                instr.encoding_flag_ = (instr.encoding_flag_ & E_NO_BREAK) | E_ENCODED;
                if (opd1.IsImm())
                {
                    instr.opcode_ = opd1.GetSize() == O_SIZE_8 ? 0xEB : 0xE9;
                }
                else
                {
                    instr.opcode_ = 0xFF;
                    instr.opd_[0] = Imm8(4);
                    instr.opd_[1] = R(opd1);
                }
                break;
            }
			case I_JCC:
            {
                auto opd1 = instr.opd_[0];
                instr.encoding_flag_ = (instr.encoding_flag_ & E_NO_BREAK) | E_ENCODED;
                switch (instr.opcode_)
                {
                case JCC_CXZ:
                    instr.opcode_ = 0x67E3;
                    break;
                case JCC_ECXZ:
                    instr.opcode_ = is64_ ? 0x67E3 : 0x00E3;
                    break;
                case JCC_RCXZ:
                    instr.opcode_ = 0x00E3;
                    break;
                default:
                    instr.opcode_ |= opd1.GetSize() == O_SIZE_8 ? 0x0070 : 0x0F80;
                    break;
                }
                break;
            }
            case I_LAR:
				break;
			case I_LEA:
				break;
			case I_LEAVE:
				break;
			case I_LLDT:
				break;
			case I_LMSW:
				break;
			case I_LSL:
				break;
			case I_LTR:
				break;
			case I_LODS_B:
				break;
			case I_LODS_W:
				break;
			case I_LODS_D:
				break;
			case I_LODS_Q:
				break;
			case I_LOOPCC:
            {
                instr.encoding_flag_ = (instr.encoding_flag_ & E_NO_BREAK) | E_ENCODED;
                switch (instr.opcode_)
                {
                case LOOP_NE:
                    instr.opcode_ = 0xE0;
                    break;
                case LOOP_E:
                    instr.opcode_ = 0xE1;
                    break;
                default:
                    instr.opcode_ = 0xE2;
                    break;
                }
                break;
            }
            case I_MOV:
            {
                auto opd1 = instr.opd_[0];
                auto opd2 = instr.opd_[1];
                bool has_imm = opd2.IsImm();
                if (has_imm)
                {
                    instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                    if (opd1.IsMem() || detail::IsInt32(opd2.GetImm()))
                    {
                        instr.opcode_ = (O_SIZE_8 == opd1.GetSize() ? 0xC6 : 0xC7);
                        instr.opd_[0] = Imm8(0);
                        instr.opd_[1] = W(opd1);
                        instr.opd_[2] = opd2;
                    }
                    else if (opd1.IsGpReg())
                    {
                        if (O_SIZE_8 == opd1.GetSize())
                        { 
                            instr.opcode_ = 0xB0;
                            instr.opd_[0] = W(opd1);
                            instr.opd_[1] = opd2;
                        }
                        else if (O_SIZE_64 == opd1.GetSize() && detail::IsInt32(opd2.GetImm()))
                        {
                            instr.opcode_ = 0xC7;
                            instr.opd_[0] = Imm8(0);
                            instr.opd_[1] = W(opd1);
                            instr.opd_[2] = Imm32(sint32(opd2.GetImm()));
                        }
                        else
                        {
                            instr.opcode_ = 0xB8;
                            instr.opd_[0] = W(opd1);
                            instr.opd_[1] = opd2;
                        }
                    }
                }
                else if (opd1.IsGpReg())
                {
                    instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                    if (opd1.GetReg().id == EAX && opd2.IsMem() && opd2.GetBase().IsInvalid() && opd2.GetIndex().IsInvalid())
                    {
                        instr.opcode_ = O_SIZE_8 == opd1.GetSize() ? 0xA0 : 0xA1;
                        if (is64_)
                        {
                            instr.opd_[0] = Imm64(sint64(opd2.GetDisp()));
                        }
                        else
                        {
                            instr.opd_[0] = Imm32(sint32(opd2.GetDisp()));
                        }
                        instr.opd_[1] = Dummy(W(opd1), Reg32(EAX));
                    }
                    else
                    {
                        instr.opcode_ = O_SIZE_8 == opd1.GetSize() ? 0x8A : 0x8B;
                        instr.opd_[0] = W(opd1);
                        instr.opd_[1] = R(opd2);
                    }
                }
                else if (opd2.IsGpReg())
                {
                    instr.encoding_flag_ = opd2.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd2.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                    if (opd2.GetReg().id == EAX && opd1.IsMem() && opd1.GetBase().IsInvalid() && opd1.GetIndex().IsInvalid())
                    {
                        instr.opcode_ = O_SIZE_8 == opd2.GetSize() ? 0xA2 : 0xA3;
                        if (is64_)
                        {
                            instr.opd_[0] = Imm64(sint64(opd1.GetDisp()));
                        }
                        else
                        {
                            instr.opd_[0] = Imm32(sint32(opd1.GetDisp()));
                        }
                        instr.opd_[1] = Dummy(R(opd2), Reg32(EAX));
                    }
                    else
                    {
                        instr.opcode_ = O_SIZE_8 == opd2.GetSize() ? 0x88 : 0x89;
                        instr.opd_[0] = R(opd2);
                        instr.opd_[1] = W(opd1);
                    }
                }
                break;
            }
            case I_MOVBE:
				break;

            case I_MOVS_B:
			case I_MOVS_W:
			case I_MOVS_D:
			case I_MOVS_Q:
				break;

            case I_MOVZX:  sub_opcode = instr.opd_[0].GetSize() == O_SIZE_8  ? 0x0FB6 : 0x0FB7; goto I_MOVZX_MOVSX_MOVSXD;
            case I_MOVSX:  sub_opcode = instr.opd_[0].GetSize() == O_SIZE_8  ? 0x0FBE : 0x0FBF; goto I_MOVZX_MOVSX_MOVSXD;
            case I_MOVSXD: sub_opcode = instr.opd_[0].GetSize() == O_SIZE_64 ? 0x0063 : 0xCC63; goto I_MOVZX_MOVSX_MOVSXD;
            I_MOVZX_MOVSX_MOVSXD:
            {
                auto opd1 = instr.opd_[0];
                auto opd2 = instr.opd_[1];
                instr.opcode_ = sub_opcode;
                instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                instr.opd_[0] = W(opd1);
                instr.opd_[1] = R(opd2);
                break;
            }
			case I_MUL:
				break;
			case I_NEG:
				break;
			case I_NOP:
				break;
			case I_NOT:
				break;
			case I_OUT:
				break;
			case I_OUTS_B:
				break;
			case I_OUTS_W:
				break;
			case I_OUTS_D:
				break;
			case I_POP:
				break;
			case I_POPAD:
				break;
			case I_POPF:
				break;
			case I_POPFD:
				break;
			case I_POPFQ:
				break;
			case I_PUSH:
				break;
			case I_PUSHAD:
				break;
			case I_PUSHF:
				break;
			case I_PUSHFD:
				break;
			case I_PUSHFQ:
				break;
			case I_RDMSR:
				break;
			case I_RDPMC:
				break;
			case I_RDTSC:
				break;
			case I_RET:
				break;

            case I_RCL:
			case I_RCR:
			case I_ROL:
			case I_ROR:
            case I_SAR:
            case I_SHL:
            case I_SHR:
                break;
                break;
			
            case I_RSM:
				break;

			case I_SCAS_B:
			case I_SCAS_W:
			case I_SCAS_D:
			case I_SCAS_Q:
				break;

            case I_SETCC:
				break;
			
            case I_SHLD:
			case I_SHRD:
				break;

            case I_SGDT:
				break;
			case I_SIDT:
				break;
			case I_SLDT:
				break;
			case I_SMSW:
				break;
			
            case I_STOS_B:
			case I_STOS_W:
			case I_STOS_D:
			case I_STOS_Q:
				break;
			
            case I_SWAPGS:
				break;
			case I_SYSCALL:
				break;
			case I_SYSENTER:
				break;
			case I_SYSEXIT:
				break;
			case I_SYSRET:
				break;
			
            case I_TEST:
            {
                auto opd1 = instr.opd_[0];
                auto opd2 = instr.opd_[1];
                instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                if (opd2.IsImm())
                {
                    if (opd1.GetReg().id == EAX && (opd1.GetSize() == O_SIZE_8 || !detail::IsInt8(opd2.GetImm())))
                    {
                        instr.opcode_ = (O_SIZE_8 == opd1.GetSize() ? 0xA8 : 0xA9);
                        instr.opd_[0] = R(opd1);
                        instr.opd_[1] = opd2;
                    }
                    else
                    {
                        instr.opcode_ = opd1.GetSize() == O_SIZE_8 ? 0xF6 : 0xF7;
                        instr.opd_[0] = Imm8(0);
                        instr.opd_[1] = R(opd1);
                        instr.opd_[2] = opd2;
                    }
                }
                else
                {
                    instr.opcode_ = (opd1.GetSize() == O_SIZE_8) ? 0x84 : 0x85;
                    instr.opd_[0] = R(opd2);
                    instr.opd_[1] = R(opd1);
                }
                break;
            }
			case I_UD2:
				break;
			case I_VERR:
				break;
			case I_VERW:
				break;
			case I_WAIT:
				break;
			case I_WBINVD:
				break;
			case I_WRMSR:
				break;
			case I_XADD:
				break;
			case I_XCHG:
            {
                auto opd1 = instr.opd_[0];
                auto opd2 = instr.opd_[1];
                auto opdX = (opd1.GetReg().id == EAX) ? opd2 : (opd2.GetReg().id == EAX) ? opd1 : detail::Opd();
                instr.encoding_flag_ = opd1.GetSize() == O_SIZE_16 ? (E_OPERAND_SIZE_PREFIX | E_ENCODED) : opd1.GetSize() == O_SIZE_64 ? (E_REXW_PREFIX | E_ENCODED) : E_ENCODED;
                if (opdX.IsNone())
                {
                    instr.opcode_ = opd1.GetSize() == O_SIZE_8 ? 0x86 : 0x87;
                    instr.opd_[0] = RW(opd1.IsMem() ? opd1 : opd2);
                    instr.opd_[1] = RW(opd1.IsMem() ? opd2 : opd1);
                }
                else
                {
                    instr.opcode_ = 0x90;
                    instr.opd_[0] = R(opdX);
                    instr.opd_[1] = detail::Opd();
                }
                break;
            }
            case I_XGETBV:
				break;
			case I_XLATB:
				break;
			case I_F2XM1:
				break;
			case I_FABS:
				break;
			case I_FADD:
				break;
			case I_FADDP:
				break;
			case I_FIADD:
				break;
			case I_FBLD:
				break;
			case I_FBSTP:
				break;
			case I_FCHS:
				break;
			case I_FCLEX:
				break;
			case I_FNCLEX:
				break;
			case I_FCMOVCC:
				break;
			case I_FCOM:
				break;
			case I_FCOMP:
				break;
			case I_FCOMPP:
				break;
			case I_FCOMI:
				break;
			case I_FCOMIP:
				break;
			case I_FCOS:
				break;
			case I_FDECSTP:
				break;
			case I_FDIV:
				break;
			case I_FDIVP:
				break;
			case I_FIDIV:
				break;
			case I_FDIVR:
				break;
			case I_FDIVRP:
				break;
			case I_FIDIVR:
				break;
			case I_FFREE:
				break;
			case I_FICOM:
				break;
			case I_FICOMP:
				break;
			case I_FILD:
				break;
			case I_FINCSTP:
				break;
			case I_FINIT:
				break;
			case I_FNINIT:
				break;
			case I_FIST:
				break;
			case I_FISTP:
				break;
			case I_FLD:
				break;
			case I_FLD1:
				break;
			case I_FLDCW:
				break;
			case I_FLDENV:
				break;
			case I_FLDL2E:
				break;
			case I_FLDL2T:
				break;
			case I_FLDLG2:
				break;
			case I_FLDLN2:
				break;
			case I_FLDPI:
				break;
			case I_FLDZ:
				break;
			case I_FMUL:
				break;
			case I_FMULP:
				break;
			case I_FIMUL:
				break;
			case I_FNOP:
				break;
			case I_FPATAN:
				break;
			case I_FPREM:
				break;
			case I_FPREM1:
				break;
			case I_FPTAN:
				break;
			case I_FRNDINT:
				break;
			case I_FRSTOR:
				break;
			case I_FSAVE:
				break;
			case I_FNSAVE:
				break;
			case I_FSCALE:
				break;
			case I_FSIN:
				break;
			case I_FSINCOS:
				break;
			case I_FSQRT:
				break;
			case I_FST:
				break;
			case I_FSTP:
				break;
			case I_FSTCW:
				break;
			case I_FNSTCW:
				break;
			case I_FSTENV:
				break;
			case I_FNSTENV:
				break;
			case I_FSTSW:
				break;
			case I_FNSTSW:
				break;
			case I_FSUB:
				break;
			case I_FSUBP:
				break;
			case I_FISUB:
				break;
			case I_FSUBR:
				break;
			case I_FSUBRP:
				break;
			case I_FISUBR:
				break;
			case I_FTST:
				break;
			case I_FUCOM:
				break;
			case I_FUCOMP:
				break;
			case I_FUCOMPP:
				break;
			case I_FUCOMI:
				break;
			case I_FUCOMIP:
				break;
			case I_FXAM:
				break;
			case I_FXCH:
				break;
			case I_FXRSTOR:
				break;
			case I_FXSAVE:
				break;
			case I_FXTRACT:
				break;
			case I_FYL2X:
				break;
			case I_FYL2XP1:
				break;
			case I_ADDPS:
				break;
			case I_ADDSS:
				break;
			case I_ADDPD:
				break;
			case I_ADDSD:
				break;
			case I_ADDSUBPS:
				break;
			case I_ADDSUBPD:
				break;
			case I_ANDPS:
				break;
			case I_ANDPD:
				break;
			case I_ANDNPS:
				break;
			case I_ANDNPD:
				break;
			case I_BLENDPS:
				break;
			case I_BLENDPD:
				break;
			case I_BLENDVPS:
				break;
			case I_BLENDVPD:
				break;
			case I_CLFLUSH:
				break;
			case I_CMPPS:
				break;
			case I_CMPSS:
				break;
			case I_CMPPD:
				break;
			case I_CMPSD:
				break;
			case I_COMISS:
				break;
			case I_COMISD:
				break;
			case I_CRC32:
				break;
			case I_CVTDQ2PD:
				break;
			case I_CVTDQ2PS:
				break;
			case I_CVTPD2DQ:
				break;
			case I_CVTPD2PI:
				break;
			case I_CVTPD2PS:
				break;
			case I_CVTPI2PD:
				break;
			case I_CVTPI2PS:
				break;
			case I_CVTPS2DQ:
				break;
			case I_CVTPS2PD:
				break;
			case I_CVTPS2PI:
				break;
			case I_CVTSD2SI:
				break;
			case I_CVTSD2SS:
				break;
			case I_CVTSI2SD:
				break;
			case I_CVTSI2SS:
				break;
			case I_CVTSS2SD:
				break;
			case I_CVTSS2SI:
				break;
			case I_CVTTPD2DQ:
				break;
			case I_CVTTPD2PI:
				break;
			case I_CVTTPS2DQ:
				break;
			case I_CVTTPS2PI:
				break;
			case I_CVTTSD2SI:
				break;
			case I_CVTTSS2SI:
				break;
			case I_DIVPS:
				break;
			case I_DIVSS:
				break;
			case I_DIVPD:
				break;
			case I_DIVSD:
				break;
			case I_DPPS:
				break;
			case I_DPPD:
				break;
			case I_EMMS:
				break;
			case I_EXTRACTPS:
				break;
			case I_FISTTP:
				break;
			case I_HADDPS:
				break;
			case I_HADDPD:
				break;
			case I_HSUBPS:
				break;
			case I_HSUBPD:
				break;
			case I_INSERTPS:
				break;
			case I_LDDQU:
				break;
			case I_LDMXCSR:
				break;
			case I_LFENCE:
				break;
			case I_MASKMOVDQU:
				break;
			case I_MASKMOVQ:
				break;
			case I_MAXPS:
				break;
			case I_MAXSS:
				break;
			case I_MAXPD:
				break;
			case I_MAXSD:
				break;
			case I_MFENCE:
				break;
			case I_MINPS:
				break;
			case I_MINSS:
				break;
			case I_MINPD:
				break;
			case I_MINSD:
				break;
			case I_MONITOR:
				break;
			case I_MOVAPD:
				break;
			case I_MOVAPS:
				break;
			case I_MOVD:
				break;
			case I_MOVDDUP:
				break;
			case I_MOVDQA:
				break;
			case I_MOVDQU:
				break;
			case I_MOVDQ2Q:
				break;
			case I_MOVHLPS:
				break;
			case I_MOVLHPS:
				break;
			case I_MOVHPS:
				break;
			case I_MOVHPD:
				break;
			case I_MOVLPS:
				break;
			case I_MOVLPD:
				break;
			case I_MOVMSKPS:
				break;
			case I_MOVMSKPD:
				break;
			case I_MOVNTDQ:
				break;
			case I_MOVNTDQA:
				break;
			case I_MOVNTI:
				break;
			case I_MOVNTPD:
				break;
			case I_MOVNTPS:
				break;
			case I_MOVNTQ:
				break;
			case I_MOVQ:
				break;
			case I_MOVQ2DQ:
				break;
			case I_MOVSD:
				break;
			case I_MOVSS:
				break;
			case I_MOVSHDUP:
				break;
			case I_MOVSLDUP:
				break;
			case I_MOVUPS:
				break;
			case I_MOVUPD:
				break;
			case I_MPSADBW:
				break;
			case I_MULPS:
				break;
			case I_MULSS:
				break;
			case I_MULPD:
				break;
			case I_MULSD:
				break;
			case I_MWAIT:
				break;
			case I_ORPS:
				break;
			case I_ORPD:
				break;
			case I_PABSB:
				break;
			case I_PABSD:
				break;
			case I_PABSW:
				break;
			case I_PACKSSDW:
				break;
			case I_PACKSSWB:
				break;
			case I_PACKUSDW:
				break;
			case I_PACKUSWB:
				break;
			case I_PADDB:
				break;
			case I_PADDD:
				break;
			case I_PADDQ:
				break;
			case I_PADDSB:
				break;
			case I_PADDSW:
				break;
			case I_PADDUSB:
				break;
			case I_PADDUSW:
				break;
			case I_PADDW:
				break;
			case I_PALIGNR:
				break;
			case I_PAND:
				break;
			case I_PANDN:
				break;
			case I_PAUSE:
				break;
			case I_PAVGB:
				break;
			case I_PAVGW:
				break;
			case I_PBLENDVB:
				break;
			case I_PBLENDW:
				break;
			case I_PCMPEQB:
				break;
			case I_PCMPEQW:
				break;
			case I_PCMPEQD:
				break;
			case I_PCMPEQQ:
				break;
			case I_PCMPESTRI:
				break;
			case I_PCMPESTRM:
				break;
			case I_PCMPISTRI:
				break;
			case I_PCMPISTRM:
				break;
			case I_PCMPGTB:
				break;
			case I_PCMPGTW:
				break;
			case I_PCMPGTD:
				break;
			case I_PCMPGTQ:
				break;
			case I_PEXTRB:
				break;
			case I_PEXTRW:
				break;
			case I_PEXTRD:
				break;
			case I_PEXTRQ:
				break;
			case I_PHADDW:
				break;
			case I_PHADDD:
				break;
			case I_PHADDSW:
				break;
			case I_PHMINPOSUW:
				break;
			case I_PHSUBW:
				break;
			case I_PHSUBD:
				break;
			case I_PHSUBSW:
				break;
			case I_PINSRB:
				break;
			case I_PINSRW:
				break;
			case I_PINSRD:
				break;
			case I_PINSRQ:
				break;
			case I_PMADDUBSW:
				break;
			case I_PMADDWD:
				break;
			case I_PMAXSB:
				break;
			case I_PMAXSW:
				break;
			case I_PMAXSD:
				break;
			case I_PMAXUB:
				break;
			case I_PMAXUW:
				break;
			case I_PMAXUD:
				break;
			case I_PMINSB:
				break;
			case I_PMINSW:
				break;
			case I_PMINSD:
				break;
			case I_PMINUB:
				break;
			case I_PMINUW:
				break;
			case I_PMINUD:
				break;
			case I_PMOVMSKB:
				break;
			case I_PMOVSXBW:
				break;
			case I_PMOVSXBD:
				break;
			case I_PMOVSXBQ:
				break;
			case I_PMOVSXWD:
				break;
			case I_PMOVSXWQ:
				break;
			case I_PMOVSXDQ:
				break;
			case I_PMOVZXBW:
				break;
			case I_PMOVZXBD:
				break;
			case I_PMOVZXBQ:
				break;
			case I_PMOVZXWD:
				break;
			case I_PMOVZXWQ:
				break;
			case I_PMOVZXDQ:
				break;
			case I_PMULDQ:
				break;
			case I_PMULHRSW:
				break;
			case I_PMULHUW:
				break;
			case I_PMULHW:
				break;
			case I_PMULLW:
				break;
			case I_PMULLD:
				break;
			case I_PMULUDQ:
				break;
			case I_POPCNT:
				break;
			case I_POR:
				break;
			case I_PREFETCH:
				break;
			case I_PSADBW:
				break;
			case I_PSHUFB:
				break;
			case I_PSHUFD:
				break;
			case I_PSHUFHW:
				break;
			case I_PSHUFLW:
				break;
			case I_PSHUFW:
				break;
			case I_PSIGNB:
				break;
			case I_PSIGNW:
				break;
			case I_PSIGND:
				break;
			case I_PSLLW:
				break;
			case I_PSLLD:
				break;
			case I_PSLLQ:
				break;
			case I_PSLLDQ:
				break;
			case I_PSRAW:
				break;
			case I_PSRAD:
				break;
			case I_PSRLW:
				break;
			case I_PSRLD:
				break;
			case I_PSRLQ:
				break;
			case I_PSRLDQ:
				break;
			case I_PSUBB:
				break;
			case I_PSUBW:
				break;
			case I_PSUBD:
				break;
			case I_PSUBQ:
				break;
			case I_PSUBSB:
				break;
			case I_PSUBSW:
				break;
			case I_PSUBUSB:
				break;
			case I_PSUBUSW:
				break;
			case I_PTEST:
				break;
			case I_PUNPCKHBW:
				break;
			case I_PUNPCKHWD:
				break;
			case I_PUNPCKHDQ:
				break;
			case I_PUNPCKHQDQ:
				break;
			case I_PUNPCKLBW:
				break;
			case I_PUNPCKLWD:
				break;
			case I_PUNPCKLDQ:
				break;
			case I_PUNPCKLQDQ:
				break;
			case I_PXOR:
				break;
			case I_RCPPS:
				break;
			case I_RCPSS:
				break;
			case I_ROUNDPS:
				break;
			case I_ROUNDPD:
				break;
			case I_ROUNDSS:
				break;
			case I_ROUNDSD:
				break;
			case I_RSQRTPS:
				break;
			case I_RSQRTSS:
				break;
			case I_SFENCE:
				break;
			case I_SHUFPS:
				break;
			case I_SHUFPD:
				break;
			case I_SQRTPS:
				break;
			case I_SQRTSS:
				break;
			case I_SQRTPD:
				break;
			case I_SQRTSD:
				break;
			case I_STMXCSR:
				break;
			case I_SUBPS:
				break;
			case I_SUBSS:
				break;
			case I_SUBPD:
				break;
			case I_SUBSD:
				break;
			case I_UCOMISS:
				break;
			case I_UCOMISD:
				break;
			case I_UNPCKHPS:
				break;
			case I_UNPCKHPD:
				break;
			case I_UNPCKLPS:
				break;
			case I_UNPCKLPD:
				break;
			case I_XORPS:
				break;
			case I_XORPD:
				break;
			case I_VBROADCASTSS:
				break;
			case I_VBROADCASTSD:
				break;
			case I_VBROADCASTF128:
				break;
			case I_VEXTRACTF128:
				break;
			case I_VINSERTF128:
				break;
			case I_VMASKMOVPS:
				break;
			case I_VMASKMOVPD:
				break;
			case I_VPERMILPD:
				break;
			case I_VPERMILPS:
				break;
			case I_VPERM2F128:
				break;
			case I_VTESTPS:
				break;
			case I_VTESTPD:
				break;
			case I_VZEROALL:
				break;
			case I_VZEROUPPER:
				break;
			case I_AESENC:
				break;
			case I_AESENCLAST:
				break;
			case I_AESDEC:
				break;
			case I_AESDECLAST:
				break;
			case I_AESIMC:
				break;
			case I_AESKEYGENASSIST:
				break;
			case I_PCLMULQDQ:
				break;

				// case FMA
			case I_VFMADD132PD:
				break;
			case I_VFMADD213PD:
				break;
			case I_VFMADD231PD:
				break;
			case I_VFMADD132PS:
				break;
			case I_VFMADD213PS:
				break;
			case I_VFMADD231PS:
				break;
			case I_VFMADD132SD:
				break;
			case I_VFMADD213SD:
				break;
			case I_VFMADD231SD:
				break;
			case I_VFMADD132SS:
				break;
			case I_VFMADD213SS:
				break;
			case I_VFMADD231SS:
				break;
			case I_VFMADDSUB132PD:
				break;
			case I_VFMADDSUB213PD:
				break;
			case I_VFMADDSUB231PD:
				break;
			case I_VFMADDSUB132PS:
				break;
			case I_VFMADDSUB213PS:
				break;
			case I_VFMADDSUB231PS:
				break;
			case I_VFMSUBADD132PD:
				break;
			case I_VFMSUBADD213PD:
				break;
			case I_VFMSUBADD231PD:
				break;
			case I_VFMSUBADD132PS:
				break;
			case I_VFMSUBADD213PS:
				break;
			case I_VFMSUBADD231PS:
				break;
			case I_VFMSUB132PD:
				break;
			case I_VFMSUB213PD:
				break;
			case I_VFMSUB231PD:
				break;
			case I_VFMSUB132PS:
				break;
			case I_VFMSUB213PS:
				break;
			case I_VFMSUB231PS:
				break;
			case I_VFMSUB132SD:
				break;
			case I_VFMSUB213SD:
				break;
			case I_VFMSUB231SD:
				break;
			case I_VFMSUB132SS:
				break;
			case I_VFMSUB213SS:
				break;
			case I_VFMSUB231SS:
				break;
			case I_VFNMADD132PD:
				break;
			case I_VFNMADD213PD:
				break;
			case I_VFNMADD231PD:
				break;
			case I_VFNMADD132PS:
				break;
			case I_VFNMADD213PS:
				break;
			case I_VFNMADD231PS:
				break;
			case I_VFNMADD132SD:
				break;
			case I_VFNMADD213SD:
				break;
			case I_VFNMADD231SD:
				break;
			case I_VFNMADD132SS:
				break;
			case I_VFNMADD213SS:
				break;
			case I_VFNMADD231SS:
				break;
			case I_VFNMSUB132PD:
				break;
			case I_VFNMSUB213PD:
				break;
			case I_VFNMSUB231PD:
				break;
			case I_VFNMSUB132PS:
				break;
			case I_VFNMSUB213PS:
				break;
			case I_VFNMSUB231PS:
				break;
			case I_VFNMSUB132SD:
				break;
			case I_VFNMSUB213SD:
				break;
			case I_VFNMSUB231SD:
				break;
			case I_VFNMSUB132SS:
				break;
			case I_VFNMSUB213SS:
				break;
			case I_VFNMSUB231SS:
				break;


				// case F16C
			case I_RDFSBASE:
				break;
			case I_RDGSBASE:
				break;
			case I_RDRAND:
				break;
			case I_WRFSBASE:
				break;
			case I_WRGSBASE:
				break;
			case I_VCVTPH2PS:
				break;
			case I_VCVTPS2PH:
				break;


				// case BMI
			case I_ANDN:
				break;
			case I_BEXTR:
				break;
			case I_BLSI:
				break;
			case I_BLSMSK:
				break;
			case I_BLSR:
				break;
			case I_BZHI:
				break;
			case I_LZCNT:
				break;
			case I_MULX:
				break;
			case I_PDEP:
				break;
			case I_PEXT:
				break;
			case I_RORX:
				break;
			case I_SARX:
				break;
			case I_SHLX:
				break;
			case I_SHRX:
				break;
			case I_TZCNT:
				break;
			case I_INVPCID:
				break;


				// case XOP
			case I_VFRCZPD:
				break;
			case I_VFRCZPS:
				break;
			case I_VFRCZSD:
				break;
			case I_VFRCZSS:
				break;
			case I_VPCMOV:
				break;
			case I_VPCOMB:
				break;
			case I_VPCOMD:
				break;
			case I_VPCOMQ:
				break;
			case I_VPCOMUB:
				break;
			case I_VPCOMUD:
				break;
			case I_VPCOMUQ:
				break;
			case I_VPCOMUW:
				break;
			case I_VPCOMW:
				break;
			case I_VPERMIL2PD:
				break;
			case I_VPERMIL2PS:
				break;
			case I_VPHADDBD:
				break;
			case I_VPHADDBQ:
				break;
			case I_VPHADDBW:
				break;
			case I_VPHADDDQ:
				break;
			case I_VPHADDUBD:
				break;
			case I_VPHADDUBQ:
				break;
			case I_VPHADDUBW:
				break;
			case I_VPHADDUDQ:
				break;
			case I_VPHADDUWD:
				break;
			case I_VPHADDUWQ:
				break;
			case I_VPHADDWD:
				break;
			case I_VPHADDWQ:
				break;
			case I_VPHSUBBW:
				break;
			case I_VPHSUBDQ:
				break;
			case I_VPHSUBWD:
				break;
			case I_VPMACSDD:
				break;
			case I_VPMACSDQH:
				break;
			case I_VPMACSDQL:
				break;
			case I_VPMACSSDD:
				break;
			case I_VPMACSSDQH:
				break;
			case I_VPMACSSDQL:
				break;
			case I_VPMACSSWD:
				break;
			case I_VPMACSSWW:
				break;
			case I_VPMACSWD:
				break;
			case I_VPMACSWW:
				break;
			case I_VPMADCSSWD:
				break;
			case I_VPMADCSWD:
				break;
			case I_VPPERM:
				break;
			case I_VPROTB:
				break;
			case I_VPROTD:
				break;
			case I_VPROTQ:
				break;
			case I_VPROTW:
				break;
			case I_VPSHAB:
				break;
			case I_VPSHAD:
				break;
			case I_VPSHAQ:
				break;
			case I_VPSHAW:
				break;
			case I_VPSHLB:
				break;
			case I_VPSHLD:
				break;
			case I_VPSHLQ:
				break;
			case I_VPSHLW:
				break;


				// case FMA4
			case I_VFMADDPD:
				break;
			case I_VFMADDPS:
				break;
			case I_VFMADDSD:
				break;
			case I_VFMADDSS:
				break;
			case I_VFMADDSUBPD:
				break;
			case I_VFMADDSUBPS:
				break;
			case I_VFMSUBADDPD:
				break;
			case I_VFMSUBADDPS:
				break;
			case I_VFMSUBPD:
				break;
			case I_VFMSUBPS:
				break;
			case I_VFMSUBSD:
				break;
			case I_VFMSUBSS:
				break;
			case I_VFNMADDPD:
				break;
			case I_VFNMADDPS:
				break;
			case I_VFNMADDSD:
				break;
			case I_VFNMADDSS:
				break;
			case I_VFNMSUBPD:
				break;
			case I_VFNMSUBPS:
				break;
			case I_VFNMSUBSD:
				break;
			case I_VFNMSUBSS:
				break;


				// case AVX2
			case I_VBROADCASTI128:
				break;
			case I_VPBROADCASTB:
				break;
			case I_VPBROADCASTW:
				break;
			case I_VPBROADCASTD:
				break;
			case I_VPBROADCASTQ:
				break;
			case I_PBLENDD:
				break;
			case I_VPERMD:
				break;
			case I_VPERMQ:
				break;
			case I_VPERMPS:
				break;
			case I_VPERMPD:
				break;
			case I_VPERM2I128:
				break;
			case I_VEXTRACTI128:
				break;
			case I_VINSERTI128:
				break;
			case I_VMASKMOVD:
				break;
			case I_VMASKMOVQ:
				break;
			case I_VPSLLVD:
				break;
			case I_VPSLLVQ:
				break;
			case I_VPSRAVD:
				break;
			case I_VPSRLVD:
				break;
			case I_VPSRLVQ:
				break;
			case I_VGATHERDPS:
				break;
			case I_VGATHERQPS:
				break;
			case I_VGATHERDPD:
				break;
			case I_VGATHERQPD:
				break;
			case I_VPGATHERDD:
				break;
			case I_VPGATHERQD:
				break;
			case I_VPGATHERDQ:
				break;
			case I_VPGATHERQQ:
				break;
			}
		}
	}
}
