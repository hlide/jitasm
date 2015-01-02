#ifndef jitasm_x86_encoder_h__
#define jitasm_x86_encoder_h__

#include "jitasm.x86.h"
namespace jitasm
{
    namespace x86
    {
        namespace encoder
        {
#ifdef JITASM_TEST
            template< typename OpdN >
            struct AddressingPtr2Mem$
            {
                jitasm::x86::OpdSize size_;
                AddressingPtr2Mem$(bool is64) : size_(is64 ? O_SIZE_64 : O_SIZE_32) {}
                Mem$<OpdN> operator[](sint32 disp)  { return Mem$<OpdN>(size_, size_, RegID::Invalid(), RegID::Invalid(), 0, disp); }
                Mem$<OpdN> operator[](uint32 disp)  { return Mem$<OpdN>(size_, size_, RegID::Invalid(), RegID::Invalid(), 0, (sint32)disp); }
                Mem$<OpdN> operator[](PhysicalRegID regid)  { return Mem$<OpdN>(size_, size_, RegID::CreatePhysicalRegID(R_TYPE_GP, regid), RegID::Invalid(), 0, 0); }
            };

            template< typename OpdN >
            struct AddressingPtr$
            {
                AddressingPtr2Mem$< OpdN > operator()(bool is64) { return AddressingPtr2Mem$< OpdN >(is64); }
            };

            static AddressingPtr$< Opd8   > byte_ptr;
            static AddressingPtr$< Opd16  > word_ptr;
            static AddressingPtr$< Opd32  > dword_ptr;
            static AddressingPtr$< Opd64  > qword_ptr;
            static AddressingPtr$< Opd128 > oword_ptr;
#endif

            template< InstrID id, size_t opcode, typename Operand, typename ...Operands >
            struct Encode$
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (Encode$< id, opcode, Operand >::Encode(instr, is64))
                    {
                        return Encode$< id, opcode, Operands... >::Encode(instr, is64);
                    }
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    Encode$< id, opcode, Operand >::Test(list, is64);
                    Encode$< id, opcode, Operands... >::Test(list, is64);
                }
#endif
            };

            template< InstrID id, size_t opcode, typename Operand >
            struct Encode$ < id, opcode, Operand >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            /////////////

            template< InstrID id, size_t opcode >
            struct Encode$ < id, opcode, None >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id));
                }
#endif
            };

            /// B...

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Bd_Ed < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Bq_Eq < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };
        
            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2, Access a3 >
            struct Encode$ < id, opcode, Bd_Gd_Gd_Ed < a0, a1, a2, a3 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    auto opd3 = instr.opd_[3];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a3 >(opd3);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    instr.opd_[3] = AlterAccess< a2 >(opd2);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2, Access a3 >
            struct Encode$ < id, opcode, Bq_Gq_Gq_Eq < a0, a1, a2, a3 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    auto opd3 = instr.opd_[3];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a3 >(opd3);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    instr.opd_[3] = AlterAccess< a2 >(opd2);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            /// E...
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Eb < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL)));
                    list.push_back(Instr(id, byte_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Eb_Gb < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL), Reg8(DL)));
                    list.push_back(Instr(id, byte_ptr(is64)[0x55555555], Reg8(DL)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Eb_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(uint8(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL), Imm8(0x55)));
                    list.push_back(Instr(id, byte_ptr(is64)[0x55555555], Imm8(0x55)));
                }
#endif
            };

            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ew < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX)));
                    list.push_back(Instr(id, word_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Ew_Gw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Reg16(DX)));
                    list.push_back(Instr(id, word_ptr(is64)[0x55555555], Reg16(DX)));
                }
#endif
            };
        
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ew_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(uint8(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Imm8(0x55)));
                    list.push_back(Instr(id, word_ptr(is64)[0x55555555], Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ew_Iw < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm16(sint16(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Imm16(0x5555)));
                    list.push_back(Instr(id, word_ptr(is64)[0x55555555], Imm16(0x5555)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ed < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX)));
                    list.push_back(Instr(id, dword_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Ed_Gd < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg32(EDX)));
                    list.push_back(Instr(id, dword_ptr(is64)[0x55555555], Reg32(EDX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ed_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(uint8(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Imm8(0x55)));
                    list.push_back(Instr(id, dword_ptr(is64)[0x55555555], Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ed_Id < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm32(sint32(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Imm32(0x55555555)));
                    list.push_back(Instr(id, dword_ptr(is64)[0x55555555], Imm32(0x55555555)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Eq < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RBX)));
                        list.push_back(Instr(id, qword_ptr(is64)[0x55555555]));
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Eq_Gq < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg32(RBX), Reg32(RDX)));
                        list.push_back(Instr(id, qword_ptr(is64)[0x55555555], Reg64(RDX)));
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Eq_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(uint8(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RBX), Imm8(0x55)));
                        list.push_back(Instr(id, qword_ptr(is64)[0x55555555], Imm8(0x55)));
                    }
                }
#endif
            };
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Eq_Id < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm32(sint32(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RBX), Imm32(0x55555555)));
                        list.push_back(Instr(id, qword_ptr(is64)[0x55555555], Imm32(0x55555555)));
                    }
                }
#endif
            };
            
            /// G...
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gb < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gb_Eb < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL), Reg8(DL)));
                    list.push_back(Instr(id, Reg8(BL), byte_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gb_Gw < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL), Reg16(DX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gb_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(BL), Imm8(0x55)));
                }
#endif
            };
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gw < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Eb < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(AX), Reg8(BL)));
                    list.push_back(Instr(id, Reg16(AX), byte_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Ew < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Reg16(DX)));
                    list.push_back(Instr(id, Reg16(BX), word_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Ew_Ib < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Reg16(DX), Imm8(0x55)));
                    list.push_back(Instr(id, Reg16(BX), word_ptr(is64)[0x55555555], Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Ew_Iw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm16(uint16(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Reg16(DX), Imm16(0x5555)));
                    list.push_back(Instr(id, Reg16(BX), word_ptr(is64)[0x55555555], Imm16(0x5555)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Gb < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(AX), Reg8(BL)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Gw < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Reg16(DX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gw_Gw_Ew < a0, a1, a2 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a2 >(opd2);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(AX), Reg16(DX), Reg16(BX)));
                    list.push_back(Instr(id, Reg16(AX), Reg16(DX), word_ptr(is64)[0x55555555]));
                }
#endif
            };
            
            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Gd < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Reg32(EDX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gw_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Imm8(0x55)));
                }
#endif
            };
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gw_Iw_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm16(uint16(opd1.GetImm()));
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), Imm16(0x5555), Imm8(0x55)));
                }
#endif
            };
            
            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Md < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), dword_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Xb < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), byte_ptr(is64)[RSI]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Xw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), word_ptr(is64)[RSI]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gw_Xd < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX), dword_ptr(is64)[RSI]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gd < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gd_Bd_Ed < a0, a1, a2> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a2 >(opd2);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gd_Ed < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg32(EDX)));
                    list.push_back(Instr(id, Reg32(EBX), dword_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gd_Ed_Bd < a0, a1, a2> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = AlterAccess< a2 >(opd2);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };
            
            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gd_Ed_Ib < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg32(EDX), Imm8(0x55)));
                    list.push_back(Instr(id, Reg32(EBX), dword_ptr(is64)[0x55555555], Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gd_Ed_Id < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm32(uint32(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg32(EDX), Imm32(0x55555555)));
                    list.push_back(Instr(id, Reg32(EBX), dword_ptr(is64)[0x55555555], Imm32(0x55555555)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gd_Gw < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg16(DX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gd_Gd < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg32(EDX)));
                }
#endif
            };
        
            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gd_Gd_Ed < a0, a1, a2 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a2 >(opd2);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EAX), Reg32(EDX), Reg32(EBX)));
                    list.push_back(Instr(id, Reg32(EAX), Reg32(EDX), dword_ptr(is64)[0x55555555]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gd_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Imm8(0x55)));
                }
#endif
            };
        
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gd_Iw_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm16(uint16(opd1.GetImm()));
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Imm16(0x5555), Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gd_Mq < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(RBX), qword_ptr(is64)[0x55555555]));
                }
#endif
            };
        
            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gdd_Mq_Gdd < a0, a1, a2 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    auto opd3 = instr.opd_[3];
                    auto opd4 = instr.opd_[4];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a0 >(opd1);
                    instr.opd_[2] = AlterAccess< a1 >(opd2);
                    instr.opd_[3] = AlterAccess< a2 >(opd3);
                    instr.opd_[4] = AlterAccess< a2 >(opd4);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX), Reg32(EBX), qword_ptr(is64)[0x55555555], Reg32(EDX), Reg32(EDX)));
                }
#endif
            };
        
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gq < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg64(RBX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gq_Bq_Eq < a0, a1, a2> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a2 >(opd2);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };
    
            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gq_Eq_Bq < a0, a1, a2> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = AlterAccess< a2 >(opd2);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gq_Eq_Ib < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RBX), Reg64(RDX), Imm8(0x55)));
                        list.push_back(Instr(id, Reg64(RBX), qword_ptr(is64)[0x55555555], Imm8(0x55)));
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gq_Eq_Id < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm32(uint32(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RBX), Reg64(RDX), Imm32(0x55555555)));
                        list.push_back(Instr(id, Reg64(RBX), qword_ptr(is64)[0x55555555], Imm32(0x55555555)));
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gq_Gq < a0, a1> >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg32(RBX), Reg32(RDX)));
                    }
                }
#endif
            };
                            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gq_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg32(RBX), Imm8(0x55)));
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Gq_Iw_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm16(uint16(opd1.GetImm()));
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg64(RBX), Imm16(0x5555), Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gq_Gq_Eq < a0, a1, a2 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a2 >(opd2);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RAX), Reg64(RDX), Reg64(RBX)));
                        list.push_back(Instr(id, Reg64(RAX), Reg64(RDX), qword_ptr(is64)[0x55555555]));
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gqq_Mo_Gqq < a0, a1, a2 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    auto opd3 = instr.opd_[3];
                    auto opd4 = instr.opd_[4];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a0 >(opd1);
                    instr.opd_[2] = AlterAccess< a1 >(opd2);
                    instr.opd_[3] = AlterAccess< a2 >(opd3);
                    instr.opd_[4] = AlterAccess< a2 >(opd4);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg64(RBX), Reg64(RBX), oword_ptr(is64)[0x55555555], Reg64(RDX), Reg64(RDX)));
                }
#endif
            };
    
            
            /// I...

            template< InstrID id, size_t opcode >
            struct Encode$ < id, opcode, Ib >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm8(uint8(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm8(0x55)));
                }
#endif
            };      
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ib_Gb < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd1);
                    instr.opd_[1] = Imm8(uint8(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm8(0x55), Reg8(DL)));
                }
#endif
            };      

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ib_Gw < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd1);
                    instr.opd_[1] = Imm8(uint8(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm8(0x55), Reg16(DX)));
                }
#endif
            };      

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ib_Gd < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd1);
                    instr.opd_[1] = Imm8(uint8(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm8(0x55), Reg32(EDX)));
                }
#endif
            };      

            /// J...

            template< InstrID id, size_t opcode >
            struct Encode$ < id, opcode, Jb >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm8(sint8(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm8(0)));
                }
#endif
            };

            template< InstrID id, size_t opcode >
            struct Encode$ < id, opcode, Jw >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm16(sint16(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm16(0)));
                }
#endif
            };


            template< InstrID id, size_t opcode >
            struct Encode$ < id, opcode, Jd >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm32(sint32(opd0.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Imm32(0)));
                }
#endif
            };

            /// M...
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Mb < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            /// X...
            
            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Xb_Yb < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, byte_ptr(is64)[RSI], byte_ptr(is64)[RDI]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Xw_Yw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, word_ptr(is64)[RSI], word_ptr(is64)[RDI]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Xd_Yd < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, dword_ptr(is64)[RSI], dword_ptr(is64)[RDI]));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Xq_Yq < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, qword_ptr(is64)[RSI], qword_ptr(is64)[RDI]));
                    }
                }
#endif
            };

            /// Y...
            
            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Yb_Gw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, byte_ptr(is64)[RDI], Reg16(DX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Yw_Gw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, word_ptr(is64)[RDI], Reg16(DX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Yd_Gw < a0, a1 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(opd0));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(opd1));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, dword_ptr(is64)[RDI], Reg16(DX)));
                }
#endif
            };

            /// Z...
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Zw < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(BX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Zd < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EBX)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Zq < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RBX)));
                    }
                }
#endif
            };

            /// Misc
            
            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, AL_Ib < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg8(AL), Imm8(0x55)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, AX_Iw < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm16(sint16(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg16(AX), Imm16(0x5555)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, EAX_Id < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm32(sint32(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    list.push_back(Instr(id, Reg32(EAX), Imm32(0x55555555)));
                }
#endif
            };

            template< InstrID id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, RAX_Id < a0 > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm32(sint32(opd1.GetImm()));
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.push_back(Instr(id, Reg64(RAX), Imm32(0x55555555)));
                    }
                }
#endif
            };

            /////////////

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group1 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group3 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    switch (code)
                    {
                    case 0: // TEST
                        instr.opd_[0] = Imm8(code);
                        instr.opd_[1] = opd0;
                        instr.opd_[2] = opd1;
                        return true;
                    case 2: // NOT
                    case 3: // NEG
                        instr.opd_[0] = Imm8(code);
                        instr.opd_[1] = opd0;
                        return true;
                    case 4: // MUL
                    case 5: // IMUL
                    case 6: // DIV
                    case 7: // IDIV
                        instr.opd_[0] = Imm8(code);
                        instr.opd_[1] = opd1;
                        instr.opd_[2] = opd0;
                        instr.opd_[3] = opd2;
                        return true;
                    default:
                        return false;
                    }
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group4 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd0;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group5 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd0;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group8 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group9 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    switch (code)
                    {
                    case 1: // CMPXCCHG8B/CMPXCCHG16B
                        {
                            auto opd0 = instr.opd_[0];
                            auto opd1 = instr.opd_[1];
                            auto opd2 = instr.opd_[2];
                            auto opd3 = instr.opd_[2];
                            auto opd4 = instr.opd_[2];
                            instr.opd_[0] = Imm8(code);
                            instr.opd_[1] = opd2;
                            instr.opd_[2] = opd0;
                            instr.opd_[3] = opd1;
                            instr.opd_[4] = opd2;
                            instr.opd_[5] = opd3;
                        }
                        return true;
                    case 6: // VMPTRLD/VMCLEAR/VMXON/RDRAND
                    case 7: // VMPTRST/VMPTRST/RDSEED
                        {
                            auto opd0 = instr.opd_[0];
                            instr.opd_[0] = Imm8(code);
                            instr.opd_[1] = opd0;
                        }
                        return true;
                    default:
                        return false;
                    }
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group15 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group17 < code > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            /////////////

            template< InstrID id, size_t opcode, size_t flags >
            struct Encode$ < id, opcode, EncodingFlags < flags > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    instr.encoding_flags_ |= flags;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            /////////////

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSb >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSw >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    instr.encoding_flags_ |= E_OPERAND_SIZE_PREFIX;
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSd >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return true;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSq >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (is64)
                    {
                        instr.encoding_flags_ |= E_REXW_PREFIX;
                        return true;
                    }
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (!is64)
                    {
                        list.clear();
                    }
                }
#endif
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, i64 >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return !is64;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.clear();
                    }
                }
#endif
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, o64 >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return is64;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    if (is64)
                    {
                        list.clear();
                    }
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t index, PhysicalRegID regid, Access access >
            struct Encode$ < id, opcode, DummyRb < index, regid, access > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (index != size_t(-1))
                    {
                        auto opdi = instr.opd_[index];
                        instr.opd_[index] = detail::Dummy(opdi, Reg8(regid));
                        return true;
                    }
                    else
                    {
                        for (size_t i = 0; i < Instr::MAX_OPERAND_COUNT; ++i)
                        {
                            auto & opdi = instr.opd_[i];
                            if (opdi.IsNone())
                            {
                                opdi = detail::Dummy(AlterAccess< access >(Reg8(regid)));
                                return true;
                            }
                        }
                    }
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t index, PhysicalRegID regid, Access access >
            struct Encode$ < id, opcode, DummyRw < index, regid, access > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (index != size_t(-1))
                    {
                        auto opdi = instr.opd_[index];
                        instr.opd_[index] = detail::Dummy(opdi, Reg16(regid));
                        return true;
                    }
                    else
                    {
                        for (size_t i = 0; i < Instr::MAX_OPERAND_COUNT; ++i)
                        {
                            auto & opdi = instr.opd_[i];
                            if (opdi.IsNone())
                            {
                                opdi = detail::Dummy(AlterAccess< access >(Reg16(regid)));
                                return true;
                            }
                        }
                    }
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t index, PhysicalRegID regid, Access access >
            struct Encode$ < id, opcode, DummyRd < index, regid, access > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (index != size_t(-1))
                    {
                        auto opdi = instr.opd_[index];
                        instr.opd_[index] = detail::Dummy(opdi, Reg32(regid));
                        return true;
                    }
                    else
                    {
                        for (size_t i = 0; i < Instr::MAX_OPERAND_COUNT; ++i)
                        {
                            auto & opdi = instr.opd_[i];
                            if (opdi.IsNone())
                            {
                                opdi = detail::Dummy(AlterAccess< access >(Reg32(regid)));
                                return true;
                            }
                        }
                    }
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            template< InstrID id, size_t opcode, size_t index, PhysicalRegID regid, Access access >
            struct Encode$ < id, opcode, DummyRq < index, regid, access > >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (is64)
                    {
                        if (index != size_t(-1))
                        {
                            auto opdi = instr.opd_[index];
                            instr.opd_[index] = detail::Dummy(opdi, Reg64(regid));
                            return true;
                        }
                        else
                        {
                            for (size_t i = 0; i < Instr::MAX_OPERAND_COUNT; ++i)
                            {
                                auto & opdi = instr.opd_[i];
                                if (opdi.IsNone())
                                {
                                    opdi = detail::Dummy(AlterAccess< access >(Reg64(regid)));
                                    return true;
                                }
                            }
                        }
                    }
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };

            /////////////

            template< InstrID id >
            struct Opcode$
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                }
#endif
            };
        }
    }
}
#endif // jitasm_x86_encoder_h__