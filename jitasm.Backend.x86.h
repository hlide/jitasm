#ifndef jitasm_Backend_x86_h__
#define jitasm_Backend_x86_h__
#include "jitasm.x86.h"
#include "jitasm.Backend.h"
namespace jitasm
{
	namespace x86
	{
		struct Backend : jitasm::Backend$CRTP < Backend >
		{
			bool is64_;

			Backend(bool is64, void* buffaddr = nullptr, size_t buffsize = 0)
                : jitasm::Backend$CRTP< Backend >(buffaddr, buffsize), is64_(is64)
			{
				memset(buffaddr, 0xCC, buffsize);
			}

			size_t SizeOf(Instr & instr)
			{
				Backend backend(is64_);
				backend.Assemble(instr);
				return backend.GetSize();
			}

			static bool HasRIP(detail::Opd const & opd)
			{
				return opd.IsMem() && (opd.GetBase().type == R_TYPE_IP);
			}

			uint8 GetWRXB(int w, detail::Opd const & reg, detail::Opd const & r_m)
			{
				uint8 wrxb = w ? 8 : 0;
				if (reg.IsReg())
				{
					if (!reg.GetReg().IsInvalid() && reg.GetReg().id >= R8) wrxb |= 4;
				}
				if (r_m.IsReg())
				{
					if (r_m.GetReg().id >= R8) wrxb |= 1;
				}
				if (r_m.IsMem())
				{
					if (!r_m.GetIndex().IsInvalid() && r_m.GetIndex().id >= R8) wrxb |= 2;
					if (!r_m.GetBase().IsInvalid() && r_m.GetBase().id >= R8) wrxb |= 1;
				}
				return wrxb;
			}

			void EncodePrefixes(uint32 flag, detail::Opd const & reg, detail::Opd const & r_m, detail::Opd const & vex)
			{
				if (flag & (E_VEX | E_XOP))
				{
					// Encode VEX prefix
					if (is64_ && r_m.IsMem() && r_m.GetAddressBaseSize() != O_SIZE_64) db(0x67);
					uint8 vvvv = vex.IsReg() ? 0xF - (uint8)vex.GetReg().id : 0xF;
					uint8 mmmmm = (flag & E_VEX_MMMMM_MASK) >> E_VEX_MMMMM_SHIFT;
					uint8 pp = static_cast<uint8>((flag & E_VEX_PP_MASK) >> E_VEX_PP_SHIFT);
					uint8 wrxb = GetWRXB(flag & E_VEX_W, reg, r_m);
					if (flag & E_XOP)
					{
						db(0x8F);
						db((~wrxb & 7) << 5 | mmmmm);
						db((wrxb & 8) << 4 | vvvv << 3 | (flag & E_VEX_L ? 4 : 0) | pp);
					}
					else if (wrxb & 0xB || (flag & E_VEX_MMMMM_MASK) == E_VEX_0F38 || (flag & E_VEX_MMMMM_MASK) == E_VEX_0F3A)
					{
						db(0xC4);
						db((~wrxb & 7) << 5 | mmmmm);
						db((wrxb & 8) << 4 | vvvv << 3 | (flag & E_VEX_L ? 4 : 0) | pp);
					}
					else
					{
						db(0xC5);
						db((~wrxb & 4) << 5 | vvvv << 3 | (flag & E_VEX_L ? 4 : 0) | pp);
					}
				}
				else
				{
					uint8 wrxb = GetWRXB(flag & E_REXW_PREFIX, reg, r_m);
					if (wrxb)
					{
						// Encode REX prefix
						if (flag & E_REP_PREFIX) db(0xF3);
						if (is64_ && r_m.IsMem() && r_m.GetAddressBaseSize() != O_SIZE_64) db(0x67);
						if (flag & E_OPERAND_SIZE_PREFIX) db(0x66);

						/**/ if (flag & E_MANDATORY_PREFIX_66) db(0x66);
						else if (flag & E_MANDATORY_PREFIX_F2) db(0xF2);
						else if (flag & E_MANDATORY_PREFIX_F3) db(0xF3);

						db(0x40 | wrxb);
					}
					else
					{
						/**/ if (flag & E_MANDATORY_PREFIX_66) db(0x66);
						else if (flag & E_MANDATORY_PREFIX_F2) db(0xF2);
						else if (flag & E_MANDATORY_PREFIX_F3) db(0xF3);

						if (flag & E_REP_PREFIX) db(0xF3);
						if (is64_ && r_m.IsMem() && r_m.GetAddressBaseSize() != O_SIZE_64) db(0x67);
						if (flag & E_OPERAND_SIZE_PREFIX) db(0x66);
					}
				}
			}

			void EncodeModRM(uint8 reg, detail::Opd const & r_m)
			{
				reg &= 0x7;

				/**/ if (r_m.IsReg())
				{
					db(0xC0 | (reg << 3) | (r_m.GetReg().id & 0x7));
				}
				else if (r_m.IsMem())
				{
					int base = r_m.GetBase().id; if (base != INVALID) base &= 0x7;
					int index = r_m.GetIndex().id; if (index != INVALID) index &= 0x7;

					if (base == INVALID && index == INVALID)
					{
						if (is64_)
						{
							db(reg << 3 | 4);
							db(0x25);
						}
						else
						{
							db(reg << 3 | 5);
						}
						dd(r_m.GetDisp());
					}
					else if (r_m.GetBase().type == R_TYPE_IP)
					{
						db(0 << 6 | reg << 3 | 5);
						dd(r_m.GetDisp());
					}
					else
					{
						if (index == ESP)
						{
							index = base;
							base = ESP;
						}
						bool sib = index != INVALID || r_m.GetScale() || base == ESP;

						// ModR/M
						uint8 mod = 0;
						/**/ if (r_m.GetDisp() == 0 || (sib && base == INVALID)) mod = base != EBP ? 0 : 1;
						else if (detail::IsInt8(r_m.GetDisp())) mod = 1;
						else if (detail::IsInt32(r_m.GetDisp())) mod = 2;
						db(mod << 6 | reg << 3 | (sib ? 4 : base));

						// SIB
						if (sib)
						{
							uint8 ss = 0;
							if (r_m.GetScale() == 0) ss = 0;
							else if (r_m.GetScale() == 2) ss = 1;
							else if (r_m.GetScale() == 4) ss = 2;
							else if (r_m.GetScale() == 8) ss = 3;
							else JITASM_ASSERT(0);
							if (index != INVALID && base != INVALID)
							{
								db(ss << 6 | index << 3 | base);
							}
							else if (base != INVALID)
							{
								db(ss << 6 | 4 << 3 | base);
							}
							else if (index != INVALID)
							{
								db(ss << 6 | index << 3 | 5);
							}
						}

						// Displacement
						if (mod == 0 && sib && base == INVALID) dd(r_m.GetDisp());
						if (mod == 1) db(r_m.GetDisp());
						if (mod == 2) dd(r_m.GetDisp());
					}
				}
			}

			void EncodeOpcode(uint32 opcode)
			{
				if (opcode & 0xFF000000) db((opcode >> 24) & 0xFF);
				if (opcode & 0xFFFF0000) db((opcode >> 16) & 0xFF);
				if (opcode & 0xFFFFFF00) db((opcode >>  8) & 0xFF);
				/**********************/ db((opcode >>  0) & 0xFF);
			}

			void EncodeImm(detail::Opd const & imm)
			{
				auto const size = imm.GetSize();
				/**/ if (size == O_SIZE_8)  db(imm.GetImm());
				else if (size == O_SIZE_16) dw(imm.GetImm());
				else if (size == O_SIZE_32) dd(imm.GetImm());
				else if (size == O_SIZE_64) dq(imm.GetImm());
			}

			void EncodeSource(detail::Opd const & imm)
			{
				AddBookmark(size_, uint64(imm.GetImm()));
			}

			void EncodeMultiNop(detail::Opd const & imm)
			{
				size_t align = 1ULL << size_t(imm.GetImm());
				size_t bytes = ((size_ + align - 1) & size_t(-intptr_t(align))) - size_;
                while (bytes > 0) 
                {
                    size_t size = bytes < 16 ? bytes : 16;
                    bytes -= size;
                    switch (size)
                    {
                    case  0: break;
                    case  1: PutBytes("\x90", 1); break;
                    case  2: PutBytes("\x66\x90", 2); break;
                    case  3: PutBytes("\x0f\x1f\x00", 3); break;
                    case  4: PutBytes("\x0f\x1f\x40\x00", 4); break;
                    case  5: PutBytes("\x0f\x1f\x44\x00\x00", 5); break;
                    case  6: PutBytes("\x66\x0f\x1f\x44\x00\x00", 6); break;
                    case  7: PutBytes("\x0f\x1f\x80\x00\x00\x00\x00", 7); break;
                    case  8: PutBytes("\x0f\x1f\x84\x00\x00\x00\x00\x00", 8); break;
                    case  9: PutBytes("\x66\x0f\x1f\x84\x00\x00\x00\x00\x00", 9); break;
                    case 10:
                    more_10: PutBytes("\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00", 10); break;
                    case 11:
                    case 12:
                    case 13:
                    case 14:
                    case 15:
                    default: PutBytes("\x66\x66\x66\x66\x66\x66", size - 10); goto more_10;
                    }
                }
			}

			void Encode(Instr const & instr)
			{
				uint32 opcode = instr.opcode_;

				auto const & opd1 = instr.GetOpd(0).IsDummy() ? detail::Opd() : instr.GetOpd(0);
				auto const & opd2 = instr.GetOpd(1).IsDummy() ? detail::Opd() : instr.GetOpd(1);
				auto const & opd3 = instr.GetOpd(2).IsDummy() ? detail::Opd() : instr.GetOpd(2);
				auto const & opd4 = instr.GetOpd(3).IsDummy() ? detail::Opd() : instr.GetOpd(3);

				// +rb, +rw, +rd, +ro
				if (opd1.IsReg() && (opd2.IsNone() || opd2.IsImm()))
				{
					opcode += opd1.GetReg().id & 0x7;
				}

				if ((opd1.IsImm() || opd1.IsReg()) && (opd2.IsReg() || opd2.IsMem()))
				{	// ModR/M
					auto const & reg = opd1;
					auto const & r_m = opd2;
					auto const & vex = opd3;
					EncodePrefixes(instr.encoding_flag_, reg, r_m, vex);
					EncodeOpcode(opcode);
					EncodeModRM((uint8)(reg.IsImm() ? reg.GetImm() : reg.GetReg().id), r_m);

					// /is4
					if (opd4.IsReg())
					{
						EncodeImm(Imm8(static_cast<uint8>(opd4.GetReg().id << 4)));
					}
				}
				else
				{
					auto const & reg = detail::Opd();
					auto const & r_m = opd1.IsReg() ? opd1 : detail::Opd();
					auto const & vex = detail::Opd();
					EncodePrefixes(instr.encoding_flag_, reg, r_m, vex);
					EncodeOpcode(opcode);
				}

				if (opd1.IsImm() && !opd2.IsReg() && !opd2.IsMem())	EncodeImm(opd1);
				if (opd2.IsImm())	EncodeImm(opd2);
				if (opd3.IsImm())	EncodeImm(opd3);
				if (opd4.IsImm())	EncodeImm(opd4);
			}

            void EncodeInstr(Instr & instr);

			void Assemble(Instr & instr)
			{
				if (0 == (instr.encoding_flag_ & E_ENCODED)) EncodeInstr(instr);

				switch (instr.GetID())
				{
				case I_ALIGN:   EncodeMultiNop(instr.GetOpd(0)); break;
				case I_NULL:                                     break;
				case I_SOURCE:  EncodeSource(instr.GetOpd(0));   break;
				case I_DB:      EncodeImm(instr.GetOpd(0));      break;
				case I_DW:      EncodeImm(instr.GetOpd(0));      break;
				case I_DD:      EncodeImm(instr.GetOpd(0));      break;
				case I_DQ:      EncodeImm(instr.GetOpd(0));      break;
				default:		Encode(instr);                   break;
				}
			}
		};
	}
}
#endif // jitasm_Backend_x86_h__