#include "jitasm.Backend.x86.h"

namespace jitasm
{
    namespace x86
    {
        namespace encoder
        {
            template< size_t id, size_t opcode, typename Operand, typename ...Operands >
            struct Encode$
            {
                static void Encode(Instr & instr)
                {
                    Encode$< id, opcode, Operand     >::Encode(instr);
                    Encode$< id, opcode, Operands... >::Encode(instr);
                }
            };

            template< size_t id, size_t opcode, typename Operand >
            struct Encode$< id, opcode, Operand >
            {
            private:
                static void Encode(Instr & instr);
            };

            /////////////

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, None >
            {
                static void Encode(Instr & instr)
                {
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, Jb >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm8(sint8(opd0.GetImm()));
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, Jz >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    if (opd0.GetSize() == O_SIZE_16) instr.opd_[0] = Imm16(sint16(opd0.GetImm()));
                    else                             instr.opd_[0] = Imm32(sint32(opd0.GetImm()));
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ev < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Zv < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Mb < a0 > >
            {
                static void Encode(Instr & instr)
                {
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Implicit_rAX < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(Reg64(RAX)));
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ib_Implicit_rAX < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    //auto opd0 = instr.opd_[0];
                    //instr.opd_[0] = opd0.GetImm();
                    instr.opd_[1] = detail::Dummy(AlterAccess< a0 >(Reg64(RAX)));
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Implicit_rDI_rSI < a0, a1 > >
            {
                static void Encode(Instr & instr)
                {
                    instr.opd_[0] = detail::Dummy(AlterAccess< a0 >(Reg64(RDI)));
                    instr.opd_[1] = detail::Dummy(AlterAccess< a1 >(Reg64(RSI)));
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Eb_Gb < a0, a1 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Ew_Gw < a0, a1 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Ev_Gv < a0, a1 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a1 >(opd1);
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gb_Eb < a0, a1 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gv_Ev < a0, a1> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gv_Ma < a0, a1> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gy_Ey < a0, a1> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, Gy_Ey_Ib < a0, a1> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = Imm8(uint8(opd2.GetImm()));
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Eb_AL_Gb < a0, a1, a2 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Ev_rAX_Gv < a0, a1, a2 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                }
            };


            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, AL_Ib < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = Imm8(uint8(opd1.GetImm()));
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, rAX_Iz < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    if (opd0.GetSize() == O_SIZE_16) instr.opd_[1] = Imm16(sint16(opd1.GetImm()));
                    else                             instr.opd_[1] = Imm32(sint32(opd1.GetImm()));
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Eb_Ib < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(uint8(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ev_Ib < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(uint8(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                }
            };

            template< size_t id, size_t opcode, Access a0 >
            struct Encode$ < id, opcode, Ev_Iz < a0 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    if (opd0.GetSize() == O_SIZE_16) instr.opd_[0] = Imm16(sint16(opd1.GetImm()));
                    else                             instr.opd_[0] = Imm32(sint32(opd1.GetImm()));
                    instr.opd_[1] = AlterAccess< a0 >(opd0);
                }
            };

            /// BMI1-BMI2
            template< size_t id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gy_By_Ey < a0, a1, a2> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a2 >(opd2);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1, Access a2 >
            struct Encode$ < id, opcode, Gy_Ey_By < a0, a1, a2> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                    instr.opd_[2] = AlterAccess< a2 >(opd2);
                }
            };

            template< size_t id, size_t opcode, Access a0, Access a1, Access a2, Access a3 >
            struct Encode$ < id, opcode, By_Gy_rDX_Ey < a0, a1, a2, a3 > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    auto opd2 = instr.opd_[2];
                    auto opd3 = instr.opd_[3];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a3 >(opd3);
                    instr.opd_[2] = AlterAccess< a1 >(opd1);
                    instr.opd_[3] = detail::Dummy(AlterAccess< a3 >(opd3), opd3);
                }
            };


            template< size_t id, size_t opcode, Access a0, Access a1 >
            struct Encode$ < id, opcode, By_Ey < a0, a1> >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = AlterAccess< a0 >(opd0);
                    instr.opd_[1] = AlterAccess< a1 >(opd1);
                }
            };

            /////////////

            template< size_t id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group1 < code > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                }
            };

            template< size_t id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group5 < code > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd0;
                }
            };

            template< size_t id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group8 < code > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                }
            };

            template< size_t id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group15 < code > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                }
            };

            template< size_t id, size_t opcode, size_t code >
            struct Encode$ < id, opcode, Group17 < code > >
            {
                static void Encode(Instr & instr)
                {
                    auto opd0 = instr.opd_[0];
                    auto opd1 = instr.opd_[1];
                    instr.opd_[0] = Imm8(code);
                    instr.opd_[1] = opd1;
                    instr.opd_[2] = opd0;
                }
            };

            /////////////

            template< size_t id, size_t opcode, size_t flags >
            struct Encode$ < id, opcode, EncodingFlags < flags > >
            {
                static void Encode(Instr & instr)
                {
                    instr.encoding_flags_ |= flags;
                }
            };

            /////////////

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSb >
            {
                static void Encode(Instr & instr)
                {
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSw >
            {
                static void Encode(Instr & instr)
                {
                    instr.encoding_flags_ |= E_OPERAND_SIZE_PREFIX;
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSq >
            {
                static void Encode(Instr & instr)
                {
                    instr.encoding_flags_ |= E_REXW_PREFIX;
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSv >
            {
                static void Encode(Instr & instr)
                {
                    switch (instr.GetOpd(0).GetSize())
                    {
                    case O_SIZE_16:
                        instr.encoding_flags_ |= E_OPERAND_SIZE_PREFIX;
                        break;
                    case O_SIZE_64:
                        instr.encoding_flags_ |= E_REXW_PREFIX;
                        break;
                    default:
                        break;
                    }
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSy >
            {
                static void Encode(Instr & instr)
                {
                    switch (instr.GetOpd(0).GetSize())
                    {
                    case O_SIZE_64:
                        instr.encoding_flags_ |= instr.encoding_flags_ & (E_VEX_128 | E_VEX_256) ? E_VEX_W1 : E_REXW_PREFIX;
                        break;
                    default:
                        break;
                    }
                }
            };

            template< size_t id, size_t opcode >
            struct Encode$ < id, opcode, OSz >
            {
                static void Encode(Instr & instr)
                {
                    switch (instr.GetOpd(0).GetSize())
                    {
                    case O_SIZE_16:
                        instr.encoding_flags_ |= E_OPERAND_SIZE_PREFIX;
                        break;
                    default:
                        break;
                    }
                }
            };

            /////////////

            template< InstrID id >
            struct Opcode$
            {
                static void Encode(Instr & instr)
                {
                    JITASM_ASSERT(0 && "unimplemented opcode");
                }
            };

            template<> struct Opcode$< I_AAA > : Opcode < I_AAA, 0x00000037, Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_AAD > : Opcode < I_AAD, 0x0000D505, Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_AAM > : Opcode < I_AAM, 0x0000D405, Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_AAS > : Opcode < I_AAS, 0x0000003F, Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_ADC > :
                Switch
                <
                /**/ Opcode < I_ADC, 0x00000012, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_ADC, 0x00000013, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_ADC, 0x00000010, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_ADC, 0x00000011, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_ADC, 0x00000014, AL_Ib < RW >, OSb >,
                /**/ Opcode < I_ADC, 0x00000080, Eb_Ib < RW >, OSb, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000083, Ev_Ib < RW >, OSv, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000015, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_ADC, 0x00000081, Ev_Iz < RW >, OSv, Group1 <2> >
                > {};

            template<> struct Opcode$< I_ADD > :
                Switch
                <
                /**/ Opcode < I_ADD, 0x00000002, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_ADD, 0x00000003, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_ADD, 0x00000000, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_ADD, 0x00000001, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_ADD, 0x00000004, AL_Ib < RW > >,
                /**/ Opcode < I_ADD, 0x00000080, Eb_Ib < RW >, OSb, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000083, Ev_Ib < RW >, OSv, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000005, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_ADD, 0x00000081, Ev_Iz < RW >, OSv, Group1 <0> >
                > {};

            template<> struct Opcode$< I_ADX > : Opcode < I_ADX, 0x000000D5, Ib_Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_AMX > : Opcode < I_AMX, 0x000000D4, Ib_Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_AND > :
                Switch
                <
                /**/ Opcode < I_AND, 0x00000022, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_AND, 0x00000023, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_AND, 0x00000020, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_AND, 0x00000021, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_AND, 0x00000024, AL_Ib < RW > >,
                /**/ Opcode < I_AND, 0x00000080, Eb_Ib < RW >, OSb, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000083, Ev_Ib < RW >, OSv, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000025, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_AND, 0x00000081, Ev_Iz < RW >, OSv, Group1 <4> >
                > {};

            template<> struct Opcode$< I_ARPL > : Opcode < I_ARPL, 0x00000063, Ew_Gw < W, R > > {};

            template<> struct Opcode$< I_BOUND > : Opcode < I_BOUND, 0x00000062, Gv_Ma < R, R >, OSz > {};

            template<> struct Opcode$< I_BSF > : Opcode < I_BSF, 0x00000FBC, Gv_Ev < W, R >, OSv > {};

            template<> struct Opcode$< I_BSR > : Opcode < I_BSR, 0x00000FBD, Gv_Ev < W, R >, OSv > {};

            template<> struct Opcode$< I_BSWAP > : Opcode < I_BSWAP, 0x00000FC8, Zv < RW >, OSv > {};

            template<> struct Opcode$< I_BT > :
                Switch
                <
                /**/ Opcode < I_BT, 0x00000FA3, Ev_Gv < W, R >, OSv >,
                /**/ Opcode < I_BT, 0x00000FBA, Ev_Ib < W >, OSv, Group8 <4> >
                > {};

            template<> struct Opcode$< I_BTC > :
                Switch
                <
                /**/ Opcode < I_BTC, 0x00000FBB, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_BTC, 0x00000FBA, Ev_Ib < RW >, OSv, Group8 <7> >
                > {};

            template<> struct Opcode$< I_BTR > :
                Switch
                <
                /**/ Opcode < I_BTR, 0x00000FB3, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_BTR, 0x00000FBA, Ev_Ib < RW >, OSv, Group8 <6> >
                > {};

            template<> struct Opcode$< I_BTS > :
                Switch
                <
                /**/ Opcode < I_BTS, 0x00000FAB, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_BTS, 0x00000FBA, Ev_Ib < RW >, OSv, Group8 <5> >
                > {};

            template<> struct Opcode$< I_CALL > :
                Switch
                <
                /**/ Opcode < I_CALL, 0x000000E8, Jz, OSz >,
                /**/ Opcode < I_CALL, 0x000000FF, Ev < R >, OSv, Group5 <2> >
                > {};

            template<> struct Opcode$< I_CBW > : Opcode < I_CBW, 0x000000098, Implicit_rAX < RW >, OSw > {};

            template<> struct Opcode$< I_CWDE > : Opcode < I_CWDE, 0x000000098, Implicit_rAX < RW > >{};

            template<> struct Opcode$< I_CDQE > : Opcode < I_CDQE, 0x000000098, Implicit_rAX < RW >, OSq > {};

            template<> struct Opcode$< I_CDQ > : Opcode < I_CDQ, 0x000000099, Implicit_rAX < RW > > {};

            template<> struct Opcode$< I_CLC > : Opcode < I_CLC, 0x0000000F8, None > {};

            template<> struct Opcode$< I_CLD > : Opcode < I_CLD, 0x0000000FC, None > {};

            template<> struct Opcode$< I_CLFLUSH > : Opcode < I_CLFLUSH, 0x000000FAE, Mb< W >, Group15 <7> >{};
            
            template<> struct Opcode$< I_CLI > : Opcode < I_CLI, 0x0000000FA, None > {};

            template<> struct Opcode$< I_CLTS > : Opcode < I_CLTS, 0x000000F06, None > {};

            template<> struct Opcode$< I_CMC > : Opcode < I_CMC, 0x0000000F5, None >{};

            template<> struct Opcode$< I_CMOVcc > : Opcode < I_CMOVcc, 0x00000F40, Gv_Ev< RW, R >, OSv > {};

            template<> struct Opcode$< I_CMP > :
                Switch
                <
                /**/ Opcode < I_CMP, 0x0000003A, Gb_Eb < R, R >, OSb >,
                /**/ Opcode < I_CMP, 0x0000003B, Gv_Ev < R, R >, OSv >,
                /**/ Opcode < I_CMP, 0x00000038, Eb_Gb < R, R >, OSb >,
                /**/ Opcode < I_CMP, 0x00000039, Ev_Gv < R, R >, OSv >,
                /**/ Opcode < I_CMP, 0x0000003C, AL_Ib < R > >,
                /**/ Opcode < I_CMP, 0x00000080, Eb_Ib < R >, OSb, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000083, Ev_Ib < R >, OSv, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x0000003D, rAX_Iz < R >, OSv >,
                /**/ Opcode < I_CMP, 0x00000081, Ev_Iz < R >, OSv, Group1 <7> >
                > {};

            template<> struct Opcode$< I_CMPS_B  > : Opcode < I_CMPS_B, 0x000000A6, Implicit_rDI_rSI < R, R > > {};

            template<> struct Opcode$< I_CMPS_W  > : Opcode < I_CMPS_W, 0x000000A7, Implicit_rDI_rSI < R, R >, OSw > {};

            template<> struct Opcode$< I_CMPS_D  > : Opcode < I_CMPS_D, 0x000000A7, Implicit_rDI_rSI < R, R > > {};

            template<> struct Opcode$< I_CMPS_Q  > : Opcode < I_CMPS_Q, 0x000000A7, Implicit_rDI_rSI < R, R >, OSq > {};

            template<> struct Opcode$< I_CMPXCHG > :
                Switch
                <
                /**/ Opcode < I_CMP, 0x0000003A, Gb_Eb < R, R >, OSb >,
                /**/ Opcode < I_CMP, 0x0000003B, Gv_Ev < R, R >, OSv >,
                /**/ Opcode < I_CMP, 0x00000038, Eb_Gb < R, R >, OSb >,
                /**/ Opcode < I_CMP, 0x00000039, Ev_Gv < R, R >, OSv >,
                /**/ Opcode < I_CMP, 0x0000003C, AL_Ib < R > >,
                /**/ Opcode < I_CMP, 0x00000080, Eb_Ib < R >, OSb, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000083, Ev_Ib < R >, OSv, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x0000003D, rAX_Iz < R >, OSv >,
                /**/ Opcode < I_CMP, 0x00000081, Ev_Iz < R >, OSv, Group1 <7> >
                > {};

            //template<> struct Opcode$< I_CMPXCHG > : OpcodeCXU < I_CMPXCHG, 0x00000FB0, Implicit_rDI_rSI < R, R > >{};


            template<> struct Opcode$< I_OR  > :
                Switch
                <
                /**/ Opcode < I_OR, 0x0000000A, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_OR, 0x0000000B, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_OR, 0x00000008, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_OR, 0x00000009, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_OR, 0x0000000C, AL_Ib < RW > >,
                /**/ Opcode < I_OR, 0x00000080, Eb_Ib < RW >, OSb, Group1 <1> >,
                /**/ Opcode < I_OR, 0x00000083, Ev_Ib < RW >, OSv, Group1 <1> >,
                /**/ Opcode < I_OR, 0x0000000D, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_OR, 0x00000081, Ev_Iz < RW >, OSv, Group1 <1> >
                > {};

            template<> struct Opcode$< I_SBB > :
                Switch
                <
                /**/ Opcode < I_SBB, 0x0000001A, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_SBB, 0x0000001B, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_SBB, 0x00000018, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_SBB, 0x00000019, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_SBB, 0x0000001C, AL_Ib < RW > >,
                /**/ Opcode < I_SBB, 0x00000080, Eb_Ib < RW >, OSb, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x00000083, Ev_Ib < RW >, OSv, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x0000001D, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_SBB, 0x00000081, Ev_Iz < RW >, OSv, Group1 <3> >
                > {};

            template<> struct Opcode$< I_SUB > :
                Switch
                <
                /**/ Opcode < I_SUB, 0x0000002A, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_SUB, 0x0000002B, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_SUB, 0x00000028, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_SUB, 0x00000029, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_SUB, 0x0000002C, AL_Ib < RW > >,
                /**/ Opcode < I_SUB, 0x00000080, Eb_Ib < RW >, OSb, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x00000083, Ev_Ib < RW >, OSv, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x0000002D, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_SUB, 0x00000081, Ev_Iz < RW >, OSv, Group1 <5> >
                > {};

            template<> struct Opcode$< I_XOR > :
                Switch
                <
                /**/ Opcode < I_XOR, 0x00000032, Gb_Eb < RW, R >, OSb >,
                /**/ Opcode < I_XOR, 0x00000033, Gv_Ev < RW, R >, OSv >,
                /**/ Opcode < I_XOR, 0x00000030, Eb_Gb < RW, R >, OSb >,
                /**/ Opcode < I_XOR, 0x00000031, Ev_Gv < RW, R >, OSv >,
                /**/ Opcode < I_XOR, 0x00000034, AL_Ib < RW > >,
                /**/ Opcode < I_XOR, 0x00000080, Eb_Ib < RW >, OSb, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000083, Ev_Ib < RW >, OSv, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000035, rAX_Iz < RW >, OSv >,
                /**/ Opcode < I_XOR, 0x00000081, Ev_Iz < RW >, OSv, Group1 <6> >
                > {};

            // Group LZCNT
            template<> struct Opcode$< I_LZCNT > : Opcode < I_LZCNT, 0x00000FBD, Gv_Ev < W, R >, EncodingFlags < E_MANDATORY_PREFIX_F3 >, OSv >{};

            // Group BIM1
            template<> struct Opcode$< I_ANDN   > : Opcode < I_ANDN, 0x000000F2, Gy_By_Ey < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_0F38 >, OSy >{};
            template<> struct Opcode$< I_BEXTR  > : Opcode < I_BEXTR, 0x000000F7, Gy_Ey_By < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_0F38 >, OSy >{};
            template<> struct Opcode$< I_BLSI   > : Opcode < I_BLSI, 0x000000F3, By_Ey < W, R >, EncodingFlags < E_VEX_LZ | E_VEX_0F38 >, OSy, Group17 < 3 > >{};
            template<> struct Opcode$< I_BLSMSK > : Opcode < I_BLSMSK, 0x000000F3, By_Ey < W, R >, EncodingFlags < E_VEX_LZ | E_VEX_0F38 >, OSy, Group17 < 2 > >{};
            template<> struct Opcode$< I_BLSR   > : Opcode < I_BLSR, 0x000000F3, By_Ey < W, R >, EncodingFlags < E_VEX_LZ | E_VEX_0F38 >, OSy, Group17 < 1 > >{};
            template<> struct Opcode$< I_TZCNT  > : Opcode < I_TZCNT, 0x00000FBC, Gv_Ev < W, R >, EncodingFlags < E_MANDATORY_PREFIX_F3 >, OSv >{};

            // Group BIM2
            template<> struct Opcode$< I_BZHI > : Opcode < I_BZHI, 0x000000F5, Gy_Ey_By < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_0F38 >, OSy >{};
            template<> struct Opcode$< I_MULX > : Opcode < I_MULX, 0x000000F6, By_Gy_rDX_Ey < W, W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_F2_0F38 >, OSy >{};
            template<> struct Opcode$< I_PDEP > : Opcode < I_PDEP, 0x000000F5, Gy_By_Ey < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_F2_0F38 >, OSy >{};
            template<> struct Opcode$< I_PEXT > : Opcode < I_PEXT, 0x000000F5, Gy_By_Ey < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_F3_0F38 >, OSy >{};
            template<> struct Opcode$< I_RORX > : Opcode < I_RORX, 0x000000F0, Gy_Ey_Ib < W, R    >, EncodingFlags < E_VEX_LZ | E_VEX_F2_0F3A >, OSy >{};
            template<> struct Opcode$< I_SARX > : Opcode < I_SARX, 0x000000F7, Gy_Ey_By < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_F3_0F38 >, OSy >{};
            template<> struct Opcode$< I_SHLX > : Opcode < I_SHLX, 0x000000F7, Gy_Ey_By < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_66_0F38 >, OSy >{};
            template<> struct Opcode$< I_SHRX > : Opcode < I_SHRX, 0x000000F7, Gy_Ey_By < W, R, R >, EncodingFlags < E_VEX_LZ | E_VEX_F2_0F38 >, OSy >{};

            // Group ADX
            template<> struct Opcode$< I_ADCX > : Opcode < I_ADCX, 0x000F38F6, Gy_Ey< RW, W >, EncodingFlags < E_MANDATORY_PREFIX_66 >, OSy >{};
            template<> struct Opcode$< I_ADOX > : Opcode < I_ADOX, 0x000F38F6, Gy_Ey< RW, W >, EncodingFlags < E_MANDATORY_PREFIX_F3 >, OSy >{};
        }

        void Backend::EncodeInstr(Instr & instr)
        {
            switch (instr.id_)
            {
            case I_AAA:                 encoder::Opcode$< I_AAA >::Encode(instr); break;
            case I_AAD:                 encoder::Opcode$< I_AAD >::Encode(instr); break;
            case I_AAM:                 encoder::Opcode$< I_AAM >::Encode(instr); break;
            case I_AAS:                 encoder::Opcode$< I_AAS >::Encode(instr); break;
            case I_FABS:                encoder::Opcode$< I_FABS >::Encode(instr); break;
            case I_ADC:                 encoder::Opcode$< I_ADC >::Encode(instr); break;
            case I_ADCX:                encoder::Opcode$< I_ADCX >::Encode(instr); break;
            case I_ADD:                 encoder::Opcode$< I_ADD >::Encode(instr); break;
            case I_ADDPD:               encoder::Opcode$< I_ADDPD >::Encode(instr); break;
            case I_ADDPS:               encoder::Opcode$< I_ADDPS >::Encode(instr); break;
            case I_ADDSD:               encoder::Opcode$< I_ADDSD >::Encode(instr); break;
            case I_ADDSS:               encoder::Opcode$< I_ADDSS >::Encode(instr); break;
            case I_ADDSUBPD:            encoder::Opcode$< I_ADDSUBPD >::Encode(instr); break;
            case I_ADDSUBPS:            encoder::Opcode$< I_ADDSUBPS >::Encode(instr); break;
            case I_FADD:                encoder::Opcode$< I_FADD >::Encode(instr); break;
            case I_FIADD:               encoder::Opcode$< I_FIADD >::Encode(instr); break;
            case I_FADDP:               encoder::Opcode$< I_FADDP >::Encode(instr); break;
            case I_ADOX:                encoder::Opcode$< I_ADOX >::Encode(instr); break;
            case I_ADX:                 encoder::Opcode$< I_ADX >::Encode(instr); break;
            case I_AESDECLAST:          encoder::Opcode$< I_AESDECLAST >::Encode(instr); break;
            case I_AESDEC:              encoder::Opcode$< I_AESDEC >::Encode(instr); break;
            case I_AESENCLAST:          encoder::Opcode$< I_AESENCLAST >::Encode(instr); break;
            case I_AESENC:              encoder::Opcode$< I_AESENC >::Encode(instr); break;
            case I_AESIMC:              encoder::Opcode$< I_AESIMC >::Encode(instr); break;
            case I_AESKEYGENASSIST:     encoder::Opcode$< I_AESKEYGENASSIST >::Encode(instr); break;
            case I_AMX:                 encoder::Opcode$< I_AMX >::Encode(instr); break;
            case I_AND:                 encoder::Opcode$< I_AND >::Encode(instr); break;
            case I_ANDN:                encoder::Opcode$< I_ANDN >::Encode(instr); break;
            case I_ANDNPD:              encoder::Opcode$< I_ANDNPD >::Encode(instr); break;
            case I_ANDNPS:              encoder::Opcode$< I_ANDNPS >::Encode(instr); break;
            case I_ANDPD:               encoder::Opcode$< I_ANDPD >::Encode(instr); break;
            case I_ANDPS:               encoder::Opcode$< I_ANDPS >::Encode(instr); break;
            case I_ARPL:                encoder::Opcode$< I_ARPL >::Encode(instr); break;
            case I_BEXTR:               encoder::Opcode$< I_BEXTR >::Encode(instr); break;
            case I_BLCFILL:             encoder::Opcode$< I_BLCFILL >::Encode(instr); break;
            case I_BLCI:                encoder::Opcode$< I_BLCI >::Encode(instr); break;
            case I_BLCIC:               encoder::Opcode$< I_BLCIC >::Encode(instr); break;
            case I_BLCMSK:              encoder::Opcode$< I_BLCMSK >::Encode(instr); break;
            case I_BLCS:                encoder::Opcode$< I_BLCS >::Encode(instr); break;
            case I_BLENDPD:             encoder::Opcode$< I_BLENDPD >::Encode(instr); break;
            case I_BLENDPS:             encoder::Opcode$< I_BLENDPS >::Encode(instr); break;
            case I_BLENDVPD:            encoder::Opcode$< I_BLENDVPD >::Encode(instr); break;
            case I_BLENDVPS:            encoder::Opcode$< I_BLENDVPS >::Encode(instr); break;
            case I_BLSFILL:             encoder::Opcode$< I_BLSFILL >::Encode(instr); break;
            case I_BLSI:                encoder::Opcode$< I_BLSI >::Encode(instr); break;
            case I_BLSIC:               encoder::Opcode$< I_BLSIC >::Encode(instr); break;
            case I_BLSMSK:              encoder::Opcode$< I_BLSMSK >::Encode(instr); break;
            case I_BLSR:                encoder::Opcode$< I_BLSR >::Encode(instr); break;
            case I_BOUND:               encoder::Opcode$< I_BOUND >::Encode(instr); break;
            case I_BSF:                 encoder::Opcode$< I_BSF >::Encode(instr); break;
            case I_BSR:                 encoder::Opcode$< I_BSR >::Encode(instr); break;
            case I_BSWAP:               encoder::Opcode$< I_BSWAP >::Encode(instr); break;
            case I_BT:                  encoder::Opcode$< I_BT >::Encode(instr); break;
            case I_BTC:                 encoder::Opcode$< I_BTC >::Encode(instr); break;
            case I_BTR:                 encoder::Opcode$< I_BTR >::Encode(instr); break;
            case I_BTS:                 encoder::Opcode$< I_BTS >::Encode(instr); break;
            case I_BZHI:                encoder::Opcode$< I_BZHI >::Encode(instr); break;
            case I_CALL:                encoder::Opcode$< I_CALL >::Encode(instr); break;
            case I_CBW:                 encoder::Opcode$< I_CBW >::Encode(instr); break;
            case I_CDQ:                 encoder::Opcode$< I_CDQ >::Encode(instr); break;
            case I_CDQE:                encoder::Opcode$< I_CDQE >::Encode(instr); break;
            case I_FCHS:                encoder::Opcode$< I_FCHS >::Encode(instr); break;
            case I_CLAC:                encoder::Opcode$< I_CLAC >::Encode(instr); break;
            case I_CLC:                 encoder::Opcode$< I_CLC >::Encode(instr); break;
            case I_CLD:                 encoder::Opcode$< I_CLD >::Encode(instr); break;
            case I_CLFLUSH:             encoder::Opcode$< I_CLFLUSH >::Encode(instr); break;
            case I_CLGI:                encoder::Opcode$< I_CLGI >::Encode(instr); break;
            case I_CLI:                 encoder::Opcode$< I_CLI >::Encode(instr); break;
            case I_CLTS:                encoder::Opcode$< I_CLTS >::Encode(instr); break;
            case I_CMC:                 encoder::Opcode$< I_CMC >::Encode(instr); break;
            case I_CMOVcc:              encoder::Opcode$< I_CMOVcc >::Encode(instr); break;
            case I_FCMOVcc:             encoder::Opcode$< I_FCMOVcc >::Encode(instr); break;
            case I_CMP:                 encoder::Opcode$< I_CMP >::Encode(instr); break;
            case I_CMPS_B:              encoder::Opcode$< I_CMPS_B >::Encode(instr); break;
            case I_CMPS_D:              encoder::Opcode$< I_CMPS_D >::Encode(instr); break;
            case I_CMPS_Q:              encoder::Opcode$< I_CMPS_Q >::Encode(instr); break;
            case I_CMPS_W:              encoder::Opcode$< I_CMPS_W >::Encode(instr); break;
            case I_CMPPD:               encoder::Opcode$< I_CMPPD >::Encode(instr); break;
            case I_CMPPS:               encoder::Opcode$< I_CMPPS >::Encode(instr); break;
            case I_CMPSD:               encoder::Opcode$< I_CMPSD >::Encode(instr); break;
            case I_CMPSS:               encoder::Opcode$< I_CMPSS >::Encode(instr); break;
            case I_CMPXCHG16B:          encoder::Opcode$< I_CMPXCHG16B >::Encode(instr); break;
            case I_CMPXCHG:             encoder::Opcode$< I_CMPXCHG >::Encode(instr); break;
            case I_CMPXCHG8B:           encoder::Opcode$< I_CMPXCHG8B >::Encode(instr); break;
            case I_COMISD:              encoder::Opcode$< I_COMISD >::Encode(instr); break;
            case I_COMISS:              encoder::Opcode$< I_COMISS >::Encode(instr); break;
            case I_FCOMP:               encoder::Opcode$< I_FCOMP >::Encode(instr); break;
            case I_FCOMPI:              encoder::Opcode$< I_FCOMPI >::Encode(instr); break;
            case I_FCOMI:               encoder::Opcode$< I_FCOMI >::Encode(instr); break;
            case I_FCOM:                encoder::Opcode$< I_FCOM >::Encode(instr); break;
            case I_FCOS:                encoder::Opcode$< I_FCOS >::Encode(instr); break;
            case I_CPUID:               encoder::Opcode$< I_CPUID >::Encode(instr); break;
            case I_CQO:                 encoder::Opcode$< I_CQO >::Encode(instr); break;
            case I_CRC32:               encoder::Opcode$< I_CRC32 >::Encode(instr); break;
            case I_CVTDQ2PD:            encoder::Opcode$< I_CVTDQ2PD >::Encode(instr); break;
            case I_CVTDQ2PS:            encoder::Opcode$< I_CVTDQ2PS >::Encode(instr); break;
            case I_CVTPD2DQ:            encoder::Opcode$< I_CVTPD2DQ >::Encode(instr); break;
            case I_CVTPD2PS:            encoder::Opcode$< I_CVTPD2PS >::Encode(instr); break;
            case I_CVTPS2DQ:            encoder::Opcode$< I_CVTPS2DQ >::Encode(instr); break;
            case I_CVTPS2PD:            encoder::Opcode$< I_CVTPS2PD >::Encode(instr); break;
            case I_CVTSD2SI:            encoder::Opcode$< I_CVTSD2SI >::Encode(instr); break;
            case I_CVTSD2SS:            encoder::Opcode$< I_CVTSD2SS >::Encode(instr); break;
            case I_CVTSI2SD:            encoder::Opcode$< I_CVTSI2SD >::Encode(instr); break;
            case I_CVTSI2SS:            encoder::Opcode$< I_CVTSI2SS >::Encode(instr); break;
            case I_CVTSS2SD:            encoder::Opcode$< I_CVTSS2SD >::Encode(instr); break;
            case I_CVTSS2SI:            encoder::Opcode$< I_CVTSS2SI >::Encode(instr); break;
            case I_CVTTPD2DQ:           encoder::Opcode$< I_CVTTPD2DQ >::Encode(instr); break;
            case I_CVTTPS2DQ:           encoder::Opcode$< I_CVTTPS2DQ >::Encode(instr); break;
            case I_CVTTSD2SI:           encoder::Opcode$< I_CVTTSD2SI >::Encode(instr); break;
            case I_CVTTSS2SI:           encoder::Opcode$< I_CVTTSS2SI >::Encode(instr); break;
            case I_CWD:                 encoder::Opcode$< I_CWD >::Encode(instr); break;
            case I_CWDE:                encoder::Opcode$< I_CWDE >::Encode(instr); break;
            case I_DAA:                 encoder::Opcode$< I_DAA >::Encode(instr); break;
            case I_DAS:                 encoder::Opcode$< I_DAS >::Encode(instr); break;
            case I_DATA16:              encoder::Opcode$< I_DATA16 >::Encode(instr); break;
            case I_DEC:                 encoder::Opcode$< I_DEC >::Encode(instr); break;
            case I_DIV:                 encoder::Opcode$< I_DIV >::Encode(instr); break;
            case I_DIVPD:               encoder::Opcode$< I_DIVPD >::Encode(instr); break;
            case I_DIVPS:               encoder::Opcode$< I_DIVPS >::Encode(instr); break;
            case I_FDIVR:               encoder::Opcode$< I_FDIVR >::Encode(instr); break;
            case I_FIDIVR:              encoder::Opcode$< I_FIDIVR >::Encode(instr); break;
            case I_FDIVRP:              encoder::Opcode$< I_FDIVRP >::Encode(instr); break;
            case I_DIVSD:               encoder::Opcode$< I_DIVSD >::Encode(instr); break;
            case I_DIVSS:               encoder::Opcode$< I_DIVSS >::Encode(instr); break;
            case I_FDIV:                encoder::Opcode$< I_FDIV >::Encode(instr); break;
            case I_FIDIV:               encoder::Opcode$< I_FIDIV >::Encode(instr); break;
            case I_FDIVP:               encoder::Opcode$< I_FDIVP >::Encode(instr); break;
            case I_DPPD:                encoder::Opcode$< I_DPPD >::Encode(instr); break;
            case I_DPPS:                encoder::Opcode$< I_DPPS >::Encode(instr); break;
            case I_RET:                 encoder::Opcode$< I_RET >::Encode(instr); break;
            case I_ENCLS:               encoder::Opcode$< I_ENCLS >::Encode(instr); break;
            case I_ENCLU:               encoder::Opcode$< I_ENCLU >::Encode(instr); break;
            case I_ENTER:               encoder::Opcode$< I_ENTER >::Encode(instr); break;
            case I_EXTRACTPS:           encoder::Opcode$< I_EXTRACTPS >::Encode(instr); break;
            case I_EXTRQ:               encoder::Opcode$< I_EXTRQ >::Encode(instr); break;
            case I_F2XM1:               encoder::Opcode$< I_F2XM1 >::Encode(instr); break;
            case I_LCALL:               encoder::Opcode$< I_LCALL >::Encode(instr); break;
            case I_LJMP:                encoder::Opcode$< I_LJMP >::Encode(instr); break;
            case I_FBLD:                encoder::Opcode$< I_FBLD >::Encode(instr); break;
            case I_FBSTP:               encoder::Opcode$< I_FBSTP >::Encode(instr); break;
            case I_FCOMPP:              encoder::Opcode$< I_FCOMPP >::Encode(instr); break;
            case I_FDECSTP:             encoder::Opcode$< I_FDECSTP >::Encode(instr); break;
            case I_FEMMS:               encoder::Opcode$< I_FEMMS >::Encode(instr); break;
            case I_FFREE:               encoder::Opcode$< I_FFREE >::Encode(instr); break;
            case I_FICOM:               encoder::Opcode$< I_FICOM >::Encode(instr); break;
            case I_FICOMP:              encoder::Opcode$< I_FICOMP >::Encode(instr); break;
            case I_FINCSTP:             encoder::Opcode$< I_FINCSTP >::Encode(instr); break;
            case I_FLDCW:               encoder::Opcode$< I_FLDCW >::Encode(instr); break;
            case I_FLDENV:              encoder::Opcode$< I_FLDENV >::Encode(instr); break;
            case I_FLDL2E:              encoder::Opcode$< I_FLDL2E >::Encode(instr); break;
            case I_FLDL2T:              encoder::Opcode$< I_FLDL2T >::Encode(instr); break;
            case I_FLDLG2:              encoder::Opcode$< I_FLDLG2 >::Encode(instr); break;
            case I_FLDLN2:              encoder::Opcode$< I_FLDLN2 >::Encode(instr); break;
            case I_FLDPI:               encoder::Opcode$< I_FLDPI >::Encode(instr); break;
            case I_FNCLEX:              encoder::Opcode$< I_FNCLEX >::Encode(instr); break;
            case I_FNINIT:              encoder::Opcode$< I_FNINIT >::Encode(instr); break;
            case I_FNOP:                encoder::Opcode$< I_FNOP >::Encode(instr); break;
            case I_FNSTCW:              encoder::Opcode$< I_FNSTCW >::Encode(instr); break;
            case I_FNSTSW:              encoder::Opcode$< I_FNSTSW >::Encode(instr); break;
            case I_FPATAN:              encoder::Opcode$< I_FPATAN >::Encode(instr); break;
            case I_FPREM:               encoder::Opcode$< I_FPREM >::Encode(instr); break;
            case I_FPREM1:              encoder::Opcode$< I_FPREM1 >::Encode(instr); break;
            case I_FPTAN:               encoder::Opcode$< I_FPTAN >::Encode(instr); break;
            case I_FRNDINT:             encoder::Opcode$< I_FRNDINT >::Encode(instr); break;
            case I_FRSTOR:              encoder::Opcode$< I_FRSTOR >::Encode(instr); break;
            case I_FNSAVE:              encoder::Opcode$< I_FNSAVE >::Encode(instr); break;
            case I_FSCALE:              encoder::Opcode$< I_FSCALE >::Encode(instr); break;
            case I_FSETPM:              encoder::Opcode$< I_FSETPM >::Encode(instr); break;
            case I_FSINCOS:             encoder::Opcode$< I_FSINCOS >::Encode(instr); break;
            case I_FNSTENV:             encoder::Opcode$< I_FNSTENV >::Encode(instr); break;
            case I_FXAM:                encoder::Opcode$< I_FXAM >::Encode(instr); break;
            case I_FXRSTOR:             encoder::Opcode$< I_FXRSTOR >::Encode(instr); break;
            case I_FXRSTOR64:           encoder::Opcode$< I_FXRSTOR64 >::Encode(instr); break;
            case I_FXSAVE:              encoder::Opcode$< I_FXSAVE >::Encode(instr); break;
            case I_FXSAVE64:            encoder::Opcode$< I_FXSAVE64 >::Encode(instr); break;
            case I_FXTRACT:             encoder::Opcode$< I_FXTRACT >::Encode(instr); break;
            case I_FYL2X:               encoder::Opcode$< I_FYL2X >::Encode(instr); break;
            case I_FYL2XP1:             encoder::Opcode$< I_FYL2XP1 >::Encode(instr); break;
            case I_MOVAPD:              encoder::Opcode$< I_MOVAPD >::Encode(instr); break;
            case I_MOVAPS:              encoder::Opcode$< I_MOVAPS >::Encode(instr); break;
            case I_ORPD:                encoder::Opcode$< I_ORPD >::Encode(instr); break;
            case I_ORPS:                encoder::Opcode$< I_ORPS >::Encode(instr); break;
            case I_VMOVAPD:             encoder::Opcode$< I_VMOVAPD >::Encode(instr); break;
            case I_VMOVAPS:             encoder::Opcode$< I_VMOVAPS >::Encode(instr); break;
            case I_XORPD:               encoder::Opcode$< I_XORPD >::Encode(instr); break;
            case I_XORPS:               encoder::Opcode$< I_XORPS >::Encode(instr); break;
            case I_GETSEC:              encoder::Opcode$< I_GETSEC >::Encode(instr); break;
            case I_HADDPD:              encoder::Opcode$< I_HADDPD >::Encode(instr); break;
            case I_HADDPS:              encoder::Opcode$< I_HADDPS >::Encode(instr); break;
            case I_HLT:                 encoder::Opcode$< I_HLT >::Encode(instr); break;
            case I_HSUBPD:              encoder::Opcode$< I_HSUBPD >::Encode(instr); break;
            case I_HSUBPS:              encoder::Opcode$< I_HSUBPS >::Encode(instr); break;
            case I_IDIV:                encoder::Opcode$< I_IDIV >::Encode(instr); break;
            case I_FILD:                encoder::Opcode$< I_FILD >::Encode(instr); break;
            case I_IMUL:                encoder::Opcode$< I_IMUL >::Encode(instr); break;
            case I_IN:                  encoder::Opcode$< I_IN >::Encode(instr); break;
            case I_INC:                 encoder::Opcode$< I_INC >::Encode(instr); break;
            case I_INSB:                encoder::Opcode$< I_INSB >::Encode(instr); break;
            case I_INSERTPS:            encoder::Opcode$< I_INSERTPS >::Encode(instr); break;
            case I_INSERTQ:             encoder::Opcode$< I_INSERTQ >::Encode(instr); break;
            case I_INSD:                encoder::Opcode$< I_INSD >::Encode(instr); break;
            case I_INSW:                encoder::Opcode$< I_INSW >::Encode(instr); break;
            case I_INT:                 encoder::Opcode$< I_INT >::Encode(instr); break;
            case I_INT1:                encoder::Opcode$< I_INT1 >::Encode(instr); break;
            case I_INT3:                encoder::Opcode$< I_INT3 >::Encode(instr); break;
            case I_INTO:                encoder::Opcode$< I_INTO >::Encode(instr); break;
            case I_INVD:                encoder::Opcode$< I_INVD >::Encode(instr); break;
            case I_INVEPT:              encoder::Opcode$< I_INVEPT >::Encode(instr); break;
            case I_INVLPG:              encoder::Opcode$< I_INVLPG >::Encode(instr); break;
            case I_INVLPGA:             encoder::Opcode$< I_INVLPGA >::Encode(instr); break;
            case I_INVPCID:             encoder::Opcode$< I_INVPCID >::Encode(instr); break;
            case I_INVVPID:             encoder::Opcode$< I_INVVPID >::Encode(instr); break;
            case I_IRET:                encoder::Opcode$< I_IRET >::Encode(instr); break;
            case I_IRETD:               encoder::Opcode$< I_IRETD >::Encode(instr); break;
            case I_IRETQ:               encoder::Opcode$< I_IRETQ >::Encode(instr); break;
            case I_FISTTP:              encoder::Opcode$< I_FISTTP >::Encode(instr); break;
            case I_FIST:                encoder::Opcode$< I_FIST >::Encode(instr); break;
            case I_FISTP:               encoder::Opcode$< I_FISTP >::Encode(instr); break;
            case I_UCOMISD:             encoder::Opcode$< I_UCOMISD >::Encode(instr); break;
            case I_UCOMISS:             encoder::Opcode$< I_UCOMISS >::Encode(instr); break;
            case I_VCMP:                encoder::Opcode$< I_VCMP >::Encode(instr); break;
            case I_VCOMISD:             encoder::Opcode$< I_VCOMISD >::Encode(instr); break;
            case I_VCOMISS:             encoder::Opcode$< I_VCOMISS >::Encode(instr); break;
            case I_VCVTSD2SS:           encoder::Opcode$< I_VCVTSD2SS >::Encode(instr); break;
            case I_VCVTSI2SD:           encoder::Opcode$< I_VCVTSI2SD >::Encode(instr); break;
            case I_VCVTSI2SS:           encoder::Opcode$< I_VCVTSI2SS >::Encode(instr); break;
            case I_VCVTSS2SD:           encoder::Opcode$< I_VCVTSS2SD >::Encode(instr); break;
            case I_VCVTTSD2SI:          encoder::Opcode$< I_VCVTTSD2SI >::Encode(instr); break;
            case I_VCVTTSD2USI:         encoder::Opcode$< I_VCVTTSD2USI >::Encode(instr); break;
            case I_VCVTTSS2SI:          encoder::Opcode$< I_VCVTTSS2SI >::Encode(instr); break;
            case I_VCVTTSS2USI:         encoder::Opcode$< I_VCVTTSS2USI >::Encode(instr); break;
            case I_VCVTUSI2SD:          encoder::Opcode$< I_VCVTUSI2SD >::Encode(instr); break;
            case I_VCVTUSI2SS:          encoder::Opcode$< I_VCVTUSI2SS >::Encode(instr); break;
            case I_VUCOMISD:            encoder::Opcode$< I_VUCOMISD >::Encode(instr); break;
            case I_VUCOMISS:            encoder::Opcode$< I_VUCOMISS >::Encode(instr); break;
            case I_JCC:                 encoder::Opcode$< I_JCC >::Encode(instr); break;
            case I_JMP:                 encoder::Opcode$< I_JMP >::Encode(instr); break;
            case I_KANDB:               encoder::Opcode$< I_KANDB >::Encode(instr); break;
            case I_KANDD:               encoder::Opcode$< I_KANDD >::Encode(instr); break;
            case I_KANDNB:              encoder::Opcode$< I_KANDNB >::Encode(instr); break;
            case I_KANDND:              encoder::Opcode$< I_KANDND >::Encode(instr); break;
            case I_KANDNQ:              encoder::Opcode$< I_KANDNQ >::Encode(instr); break;
            case I_KANDNW:              encoder::Opcode$< I_KANDNW >::Encode(instr); break;
            case I_KANDQ:               encoder::Opcode$< I_KANDQ >::Encode(instr); break;
            case I_KANDW:               encoder::Opcode$< I_KANDW >::Encode(instr); break;
            case I_KMOVB:               encoder::Opcode$< I_KMOVB >::Encode(instr); break;
            case I_KMOVD:               encoder::Opcode$< I_KMOVD >::Encode(instr); break;
            case I_KMOVQ:               encoder::Opcode$< I_KMOVQ >::Encode(instr); break;
            case I_KMOVW:               encoder::Opcode$< I_KMOVW >::Encode(instr); break;
            case I_KNOTB:               encoder::Opcode$< I_KNOTB >::Encode(instr); break;
            case I_KNOTD:               encoder::Opcode$< I_KNOTD >::Encode(instr); break;
            case I_KNOTQ:               encoder::Opcode$< I_KNOTQ >::Encode(instr); break;
            case I_KNOTW:               encoder::Opcode$< I_KNOTW >::Encode(instr); break;
            case I_KORB:                encoder::Opcode$< I_KORB >::Encode(instr); break;
            case I_KORD:                encoder::Opcode$< I_KORD >::Encode(instr); break;
            case I_KORQ:                encoder::Opcode$< I_KORQ >::Encode(instr); break;
            case I_KORTESTW:            encoder::Opcode$< I_KORTESTW >::Encode(instr); break;
            case I_KORW:                encoder::Opcode$< I_KORW >::Encode(instr); break;
            case I_KSHIFTLW:            encoder::Opcode$< I_KSHIFTLW >::Encode(instr); break;
            case I_KSHIFTRW:            encoder::Opcode$< I_KSHIFTRW >::Encode(instr); break;
            case I_KUNPCKBW:            encoder::Opcode$< I_KUNPCKBW >::Encode(instr); break;
            case I_KXNORB:              encoder::Opcode$< I_KXNORB >::Encode(instr); break;
            case I_KXNORD:              encoder::Opcode$< I_KXNORD >::Encode(instr); break;
            case I_KXNORQ:              encoder::Opcode$< I_KXNORQ >::Encode(instr); break;
            case I_KXNORW:              encoder::Opcode$< I_KXNORW >::Encode(instr); break;
            case I_KXORB:               encoder::Opcode$< I_KXORB >::Encode(instr); break;
            case I_KXORD:               encoder::Opcode$< I_KXORD >::Encode(instr); break;
            case I_KXORQ:               encoder::Opcode$< I_KXORQ >::Encode(instr); break;
            case I_KXORW:               encoder::Opcode$< I_KXORW >::Encode(instr); break;
            case I_LAHF:                encoder::Opcode$< I_LAHF >::Encode(instr); break;
            case I_LAR:                 encoder::Opcode$< I_LAR >::Encode(instr); break;
            case I_LDDQU:               encoder::Opcode$< I_LDDQU >::Encode(instr); break;
            case I_LDMXCSR:             encoder::Opcode$< I_LDMXCSR >::Encode(instr); break;
            case I_LDS:                 encoder::Opcode$< I_LDS >::Encode(instr); break;
            case I_FLDZ:                encoder::Opcode$< I_FLDZ >::Encode(instr); break;
            case I_FLD1:                encoder::Opcode$< I_FLD1 >::Encode(instr); break;
            case I_FLD:                 encoder::Opcode$< I_FLD >::Encode(instr); break;
            case I_LEA:                 encoder::Opcode$< I_LEA >::Encode(instr); break;
            case I_LEAVE:               encoder::Opcode$< I_LEAVE >::Encode(instr); break;
            case I_LES:                 encoder::Opcode$< I_LES >::Encode(instr); break;
            case I_LFENCE:              encoder::Opcode$< I_LFENCE >::Encode(instr); break;
            case I_LFS:                 encoder::Opcode$< I_LFS >::Encode(instr); break;
            case I_LGDT:                encoder::Opcode$< I_LGDT >::Encode(instr); break;
            case I_LGS:                 encoder::Opcode$< I_LGS >::Encode(instr); break;
            case I_LIDT:                encoder::Opcode$< I_LIDT >::Encode(instr); break;
            case I_LLDT:                encoder::Opcode$< I_LLDT >::Encode(instr); break;
            case I_LMSW:                encoder::Opcode$< I_LMSW >::Encode(instr); break;
            case I_OR:                  encoder::Opcode$< I_OR >::Encode(instr); break;
            case I_LOCK:                encoder::Opcode$< I_LOCK >::Encode(instr); break;
            case I_SUB:                 encoder::Opcode$< I_SUB >::Encode(instr); break;
            case I_XOR:                 encoder::Opcode$< I_XOR >::Encode(instr); break;
            case I_LODSB:               encoder::Opcode$< I_LODSB >::Encode(instr); break;
            case I_LODSD:               encoder::Opcode$< I_LODSD >::Encode(instr); break;
            case I_LODSQ:               encoder::Opcode$< I_LODSQ >::Encode(instr); break;
            case I_LODSW:               encoder::Opcode$< I_LODSW >::Encode(instr); break;
            case I_LOOPCC:              encoder::Opcode$< I_LOOPCC >::Encode(instr); break;
            case I_RETF:                encoder::Opcode$< I_RETF >::Encode(instr); break;
            case I_RETFQ:               encoder::Opcode$< I_RETFQ >::Encode(instr); break;
            case I_LSL:                 encoder::Opcode$< I_LSL >::Encode(instr); break;
            case I_LSS:                 encoder::Opcode$< I_LSS >::Encode(instr); break;
            case I_LTR:                 encoder::Opcode$< I_LTR >::Encode(instr); break;
            case I_XADD:                encoder::Opcode$< I_XADD >::Encode(instr); break;
            case I_LZCNT:               encoder::Opcode$< I_LZCNT >::Encode(instr); break;
            case I_MASKMOVDQU:          encoder::Opcode$< I_MASKMOVDQU >::Encode(instr); break;
            case I_MAXPD:               encoder::Opcode$< I_MAXPD >::Encode(instr); break;
            case I_MAXPS:               encoder::Opcode$< I_MAXPS >::Encode(instr); break;
            case I_MAXSD:               encoder::Opcode$< I_MAXSD >::Encode(instr); break;
            case I_MAXSS:               encoder::Opcode$< I_MAXSS >::Encode(instr); break;
            case I_MFENCE:              encoder::Opcode$< I_MFENCE >::Encode(instr); break;
            case I_MINPD:               encoder::Opcode$< I_MINPD >::Encode(instr); break;
            case I_MINPS:               encoder::Opcode$< I_MINPS >::Encode(instr); break;
            case I_MINSD:               encoder::Opcode$< I_MINSD >::Encode(instr); break;
            case I_MINSS:               encoder::Opcode$< I_MINSS >::Encode(instr); break;
            case I_CVTPD2PI:            encoder::Opcode$< I_CVTPD2PI >::Encode(instr); break;
            case I_CVTPI2PD:            encoder::Opcode$< I_CVTPI2PD >::Encode(instr); break;
            case I_CVTPI2PS:            encoder::Opcode$< I_CVTPI2PS >::Encode(instr); break;
            case I_CVTPS2PI:            encoder::Opcode$< I_CVTPS2PI >::Encode(instr); break;
            case I_CVTTPD2PI:           encoder::Opcode$< I_CVTTPD2PI >::Encode(instr); break;
            case I_CVTTPS2PI:           encoder::Opcode$< I_CVTTPS2PI >::Encode(instr); break;
            case I_EMMS:                encoder::Opcode$< I_EMMS >::Encode(instr); break;
            case I_MASKMOVQ:            encoder::Opcode$< I_MASKMOVQ >::Encode(instr); break;
            case I_MOVD:                encoder::Opcode$< I_MOVD >::Encode(instr); break;
            case I_MOVDQ2Q:             encoder::Opcode$< I_MOVDQ2Q >::Encode(instr); break;
            case I_MOVNTQ:              encoder::Opcode$< I_MOVNTQ >::Encode(instr); break;
            case I_MOVQ2DQ:             encoder::Opcode$< I_MOVQ2DQ >::Encode(instr); break;
            case I_MOVQ:                encoder::Opcode$< I_MOVQ >::Encode(instr); break;
            case I_PABSB:               encoder::Opcode$< I_PABSB >::Encode(instr); break;
            case I_PABSD:               encoder::Opcode$< I_PABSD >::Encode(instr); break;
            case I_PABSW:               encoder::Opcode$< I_PABSW >::Encode(instr); break;
            case I_PACKSSDW:            encoder::Opcode$< I_PACKSSDW >::Encode(instr); break;
            case I_PACKSSWB:            encoder::Opcode$< I_PACKSSWB >::Encode(instr); break;
            case I_PACKUSWB:            encoder::Opcode$< I_PACKUSWB >::Encode(instr); break;
            case I_PADDB:               encoder::Opcode$< I_PADDB >::Encode(instr); break;
            case I_PADDD:               encoder::Opcode$< I_PADDD >::Encode(instr); break;
            case I_PADDQ:               encoder::Opcode$< I_PADDQ >::Encode(instr); break;
            case I_PADDSB:              encoder::Opcode$< I_PADDSB >::Encode(instr); break;
            case I_PADDSW:              encoder::Opcode$< I_PADDSW >::Encode(instr); break;
            case I_PADDUSB:             encoder::Opcode$< I_PADDUSB >::Encode(instr); break;
            case I_PADDUSW:             encoder::Opcode$< I_PADDUSW >::Encode(instr); break;
            case I_PADDW:               encoder::Opcode$< I_PADDW >::Encode(instr); break;
            case I_PALIGNR:             encoder::Opcode$< I_PALIGNR >::Encode(instr); break;
            case I_PANDN:               encoder::Opcode$< I_PANDN >::Encode(instr); break;
            case I_PAND:                encoder::Opcode$< I_PAND >::Encode(instr); break;
            case I_PAVGB:               encoder::Opcode$< I_PAVGB >::Encode(instr); break;
            case I_PAVGW:               encoder::Opcode$< I_PAVGW >::Encode(instr); break;
            case I_PCMPEQB:             encoder::Opcode$< I_PCMPEQB >::Encode(instr); break;
            case I_PCMPEQD:             encoder::Opcode$< I_PCMPEQD >::Encode(instr); break;
            case I_PCMPEQW:             encoder::Opcode$< I_PCMPEQW >::Encode(instr); break;
            case I_PCMPGTB:             encoder::Opcode$< I_PCMPGTB >::Encode(instr); break;
            case I_PCMPGTD:             encoder::Opcode$< I_PCMPGTD >::Encode(instr); break;
            case I_PCMPGTW:             encoder::Opcode$< I_PCMPGTW >::Encode(instr); break;
            case I_PEXTRW:              encoder::Opcode$< I_PEXTRW >::Encode(instr); break;
            case I_PHADDSW:             encoder::Opcode$< I_PHADDSW >::Encode(instr); break;
            case I_PHADDW:              encoder::Opcode$< I_PHADDW >::Encode(instr); break;
            case I_PHADDD:              encoder::Opcode$< I_PHADDD >::Encode(instr); break;
            case I_PHSUBD:              encoder::Opcode$< I_PHSUBD >::Encode(instr); break;
            case I_PHSUBSW:             encoder::Opcode$< I_PHSUBSW >::Encode(instr); break;
            case I_PHSUBW:              encoder::Opcode$< I_PHSUBW >::Encode(instr); break;
            case I_PINSRW:              encoder::Opcode$< I_PINSRW >::Encode(instr); break;
            case I_PMADDUBSW:           encoder::Opcode$< I_PMADDUBSW >::Encode(instr); break;
            case I_PMADDWD:             encoder::Opcode$< I_PMADDWD >::Encode(instr); break;
            case I_PMAXSW:              encoder::Opcode$< I_PMAXSW >::Encode(instr); break;
            case I_PMAXUB:              encoder::Opcode$< I_PMAXUB >::Encode(instr); break;
            case I_PMINSW:              encoder::Opcode$< I_PMINSW >::Encode(instr); break;
            case I_PMINUB:              encoder::Opcode$< I_PMINUB >::Encode(instr); break;
            case I_PMOVMSKB:            encoder::Opcode$< I_PMOVMSKB >::Encode(instr); break;
            case I_PMULHRSW:            encoder::Opcode$< I_PMULHRSW >::Encode(instr); break;
            case I_PMULHUW:             encoder::Opcode$< I_PMULHUW >::Encode(instr); break;
            case I_PMULHW:              encoder::Opcode$< I_PMULHW >::Encode(instr); break;
            case I_PMULLW:              encoder::Opcode$< I_PMULLW >::Encode(instr); break;
            case I_PMULUDQ:             encoder::Opcode$< I_PMULUDQ >::Encode(instr); break;
            case I_POR:                 encoder::Opcode$< I_POR >::Encode(instr); break;
            case I_PSADBW:              encoder::Opcode$< I_PSADBW >::Encode(instr); break;
            case I_PSHUFB:              encoder::Opcode$< I_PSHUFB >::Encode(instr); break;
            case I_PSHUFW:              encoder::Opcode$< I_PSHUFW >::Encode(instr); break;
            case I_PSIGNB:              encoder::Opcode$< I_PSIGNB >::Encode(instr); break;
            case I_PSIGND:              encoder::Opcode$< I_PSIGND >::Encode(instr); break;
            case I_PSIGNW:              encoder::Opcode$< I_PSIGNW >::Encode(instr); break;
            case I_PSLLD:               encoder::Opcode$< I_PSLLD >::Encode(instr); break;
            case I_PSLLQ:               encoder::Opcode$< I_PSLLQ >::Encode(instr); break;
            case I_PSLLW:               encoder::Opcode$< I_PSLLW >::Encode(instr); break;
            case I_PSRAD:               encoder::Opcode$< I_PSRAD >::Encode(instr); break;
            case I_PSRAW:               encoder::Opcode$< I_PSRAW >::Encode(instr); break;
            case I_PSRLD:               encoder::Opcode$< I_PSRLD >::Encode(instr); break;
            case I_PSRLQ:               encoder::Opcode$< I_PSRLQ >::Encode(instr); break;
            case I_PSRLW:               encoder::Opcode$< I_PSRLW >::Encode(instr); break;
            case I_PSUBB:               encoder::Opcode$< I_PSUBB >::Encode(instr); break;
            case I_PSUBD:               encoder::Opcode$< I_PSUBD >::Encode(instr); break;
            case I_PSUBQ:               encoder::Opcode$< I_PSUBQ >::Encode(instr); break;
            case I_PSUBSB:              encoder::Opcode$< I_PSUBSB >::Encode(instr); break;
            case I_PSUBSW:              encoder::Opcode$< I_PSUBSW >::Encode(instr); break;
            case I_PSUBUSB:             encoder::Opcode$< I_PSUBUSB >::Encode(instr); break;
            case I_PSUBUSW:             encoder::Opcode$< I_PSUBUSW >::Encode(instr); break;
            case I_PSUBW:               encoder::Opcode$< I_PSUBW >::Encode(instr); break;
            case I_PUNPCKHBW:           encoder::Opcode$< I_PUNPCKHBW >::Encode(instr); break;
            case I_PUNPCKHDQ:           encoder::Opcode$< I_PUNPCKHDQ >::Encode(instr); break;
            case I_PUNPCKHWD:           encoder::Opcode$< I_PUNPCKHWD >::Encode(instr); break;
            case I_PUNPCKLBW:           encoder::Opcode$< I_PUNPCKLBW >::Encode(instr); break;
            case I_PUNPCKLDQ:           encoder::Opcode$< I_PUNPCKLDQ >::Encode(instr); break;
            case I_PUNPCKLWD:           encoder::Opcode$< I_PUNPCKLWD >::Encode(instr); break;
            case I_PXOR:                encoder::Opcode$< I_PXOR >::Encode(instr); break;
            case I_MONITOR:             encoder::Opcode$< I_MONITOR >::Encode(instr); break;
            case I_MONTMUL:             encoder::Opcode$< I_MONTMUL >::Encode(instr); break;
            case I_MOV:                 encoder::Opcode$< I_MOV >::Encode(instr); break;
            case I_MOVABS:              encoder::Opcode$< I_MOVABS >::Encode(instr); break;
            case I_MOVBE:               encoder::Opcode$< I_MOVBE >::Encode(instr); break;
            case I_MOVDDUP:             encoder::Opcode$< I_MOVDDUP >::Encode(instr); break;
            case I_MOVDQA:              encoder::Opcode$< I_MOVDQA >::Encode(instr); break;
            case I_MOVDQU:              encoder::Opcode$< I_MOVDQU >::Encode(instr); break;
            case I_MOVHLPS:             encoder::Opcode$< I_MOVHLPS >::Encode(instr); break;
            case I_MOVHPD:              encoder::Opcode$< I_MOVHPD >::Encode(instr); break;
            case I_MOVHPS:              encoder::Opcode$< I_MOVHPS >::Encode(instr); break;
            case I_MOVLHPS:             encoder::Opcode$< I_MOVLHPS >::Encode(instr); break;
            case I_MOVLPD:              encoder::Opcode$< I_MOVLPD >::Encode(instr); break;
            case I_MOVLPS:              encoder::Opcode$< I_MOVLPS >::Encode(instr); break;
            case I_MOVMSKPD:            encoder::Opcode$< I_MOVMSKPD >::Encode(instr); break;
            case I_MOVMSKPS:            encoder::Opcode$< I_MOVMSKPS >::Encode(instr); break;
            case I_MOVNTDQA:            encoder::Opcode$< I_MOVNTDQA >::Encode(instr); break;
            case I_MOVNTDQ:             encoder::Opcode$< I_MOVNTDQ >::Encode(instr); break;
            case I_MOVNTI:              encoder::Opcode$< I_MOVNTI >::Encode(instr); break;
            case I_MOVNTPD:             encoder::Opcode$< I_MOVNTPD >::Encode(instr); break;
            case I_MOVNTPS:             encoder::Opcode$< I_MOVNTPS >::Encode(instr); break;
            case I_MOVNTSD:             encoder::Opcode$< I_MOVNTSD >::Encode(instr); break;
            case I_MOVNTSS:             encoder::Opcode$< I_MOVNTSS >::Encode(instr); break;
            case I_MOVSB:               encoder::Opcode$< I_MOVSB >::Encode(instr); break;
            case I_MOVSD:               encoder::Opcode$< I_MOVSD >::Encode(instr); break;
            case I_MOVSHDUP:            encoder::Opcode$< I_MOVSHDUP >::Encode(instr); break;
            case I_MOVSLDUP:            encoder::Opcode$< I_MOVSLDUP >::Encode(instr); break;
            case I_MOVSQ:               encoder::Opcode$< I_MOVSQ >::Encode(instr); break;
            case I_MOVSS:               encoder::Opcode$< I_MOVSS >::Encode(instr); break;
            case I_MOVSW:               encoder::Opcode$< I_MOVSW >::Encode(instr); break;
            case I_MOVSX:               encoder::Opcode$< I_MOVSX >::Encode(instr); break;
            case I_MOVSXD:              encoder::Opcode$< I_MOVSXD >::Encode(instr); break;
            case I_MOVUPD:              encoder::Opcode$< I_MOVUPD >::Encode(instr); break;
            case I_MOVUPS:              encoder::Opcode$< I_MOVUPS >::Encode(instr); break;
            case I_MOVZX:               encoder::Opcode$< I_MOVZX >::Encode(instr); break;
            case I_MPSADBW:             encoder::Opcode$< I_MPSADBW >::Encode(instr); break;
            case I_MUL:                 encoder::Opcode$< I_MUL >::Encode(instr); break;
            case I_MULPD:               encoder::Opcode$< I_MULPD >::Encode(instr); break;
            case I_MULPS:               encoder::Opcode$< I_MULPS >::Encode(instr); break;
            case I_MULSD:               encoder::Opcode$< I_MULSD >::Encode(instr); break;
            case I_MULSS:               encoder::Opcode$< I_MULSS >::Encode(instr); break;
            case I_MULX:                encoder::Opcode$< I_MULX >::Encode(instr); break;
            case I_FMUL:                encoder::Opcode$< I_FMUL >::Encode(instr); break;
            case I_FIMUL:               encoder::Opcode$< I_FIMUL >::Encode(instr); break;
            case I_FMULP:               encoder::Opcode$< I_FMULP >::Encode(instr); break;
            case I_MWAIT:               encoder::Opcode$< I_MWAIT >::Encode(instr); break;
            case I_NEG:                 encoder::Opcode$< I_NEG >::Encode(instr); break;
            case I_NOP:                 encoder::Opcode$< I_NOP >::Encode(instr); break;
            case I_NOT:                 encoder::Opcode$< I_NOT >::Encode(instr); break;
            case I_OUT:                 encoder::Opcode$< I_OUT >::Encode(instr); break;
            case I_OUTSB:               encoder::Opcode$< I_OUTSB >::Encode(instr); break;
            case I_OUTSD:               encoder::Opcode$< I_OUTSD >::Encode(instr); break;
            case I_OUTSW:               encoder::Opcode$< I_OUTSW >::Encode(instr); break;
            case I_PACKUSDW:            encoder::Opcode$< I_PACKUSDW >::Encode(instr); break;
            case I_PAUSE:               encoder::Opcode$< I_PAUSE >::Encode(instr); break;
            case I_PAVGUSB:             encoder::Opcode$< I_PAVGUSB >::Encode(instr); break;
            case I_PBLENDVB:            encoder::Opcode$< I_PBLENDVB >::Encode(instr); break;
            case I_PBLENDW:             encoder::Opcode$< I_PBLENDW >::Encode(instr); break;
            case I_PCLMULQDQ:           encoder::Opcode$< I_PCLMULQDQ >::Encode(instr); break;
            case I_PCMPEQQ:             encoder::Opcode$< I_PCMPEQQ >::Encode(instr); break;
            case I_PCMPESTRI:           encoder::Opcode$< I_PCMPESTRI >::Encode(instr); break;
            case I_PCMPESTRM:           encoder::Opcode$< I_PCMPESTRM >::Encode(instr); break;
            case I_PCMPGTQ:             encoder::Opcode$< I_PCMPGTQ >::Encode(instr); break;
            case I_PCMPISTRI:           encoder::Opcode$< I_PCMPISTRI >::Encode(instr); break;
            case I_PCMPISTRM:           encoder::Opcode$< I_PCMPISTRM >::Encode(instr); break;
            case I_PDEP:                encoder::Opcode$< I_PDEP >::Encode(instr); break;
            case I_PEXT:                encoder::Opcode$< I_PEXT >::Encode(instr); break;
            case I_PEXTRB:              encoder::Opcode$< I_PEXTRB >::Encode(instr); break;
            case I_PEXTRD:              encoder::Opcode$< I_PEXTRD >::Encode(instr); break;
            case I_PEXTRQ:              encoder::Opcode$< I_PEXTRQ >::Encode(instr); break;
            case I_PF2ID:               encoder::Opcode$< I_PF2ID >::Encode(instr); break;
            case I_PF2IW:               encoder::Opcode$< I_PF2IW >::Encode(instr); break;
            case I_PFACC:               encoder::Opcode$< I_PFACC >::Encode(instr); break;
            case I_PFADD:               encoder::Opcode$< I_PFADD >::Encode(instr); break;
            case I_PFCMPEQ:             encoder::Opcode$< I_PFCMPEQ >::Encode(instr); break;
            case I_PFCMPGE:             encoder::Opcode$< I_PFCMPGE >::Encode(instr); break;
            case I_PFCMPGT:             encoder::Opcode$< I_PFCMPGT >::Encode(instr); break;
            case I_PFMAX:               encoder::Opcode$< I_PFMAX >::Encode(instr); break;
            case I_PFMIN:               encoder::Opcode$< I_PFMIN >::Encode(instr); break;
            case I_PFMUL:               encoder::Opcode$< I_PFMUL >::Encode(instr); break;
            case I_PFNACC:              encoder::Opcode$< I_PFNACC >::Encode(instr); break;
            case I_PFPNACC:             encoder::Opcode$< I_PFPNACC >::Encode(instr); break;
            case I_PFRCPIT1:            encoder::Opcode$< I_PFRCPIT1 >::Encode(instr); break;
            case I_PFRCPIT2:            encoder::Opcode$< I_PFRCPIT2 >::Encode(instr); break;
            case I_PFRCP:               encoder::Opcode$< I_PFRCP >::Encode(instr); break;
            case I_PFRSQIT1:            encoder::Opcode$< I_PFRSQIT1 >::Encode(instr); break;
            case I_PFRSQRT:             encoder::Opcode$< I_PFRSQRT >::Encode(instr); break;
            case I_PFSUBR:              encoder::Opcode$< I_PFSUBR >::Encode(instr); break;
            case I_PFSUB:               encoder::Opcode$< I_PFSUB >::Encode(instr); break;
            case I_PHMINPOSUW:          encoder::Opcode$< I_PHMINPOSUW >::Encode(instr); break;
            case I_PI2FD:               encoder::Opcode$< I_PI2FD >::Encode(instr); break;
            case I_PI2FW:               encoder::Opcode$< I_PI2FW >::Encode(instr); break;
            case I_PINSRB:              encoder::Opcode$< I_PINSRB >::Encode(instr); break;
            case I_PINSRD:              encoder::Opcode$< I_PINSRD >::Encode(instr); break;
            case I_PINSRQ:              encoder::Opcode$< I_PINSRQ >::Encode(instr); break;
            case I_PMAXSB:              encoder::Opcode$< I_PMAXSB >::Encode(instr); break;
            case I_PMAXSD:              encoder::Opcode$< I_PMAXSD >::Encode(instr); break;
            case I_PMAXUD:              encoder::Opcode$< I_PMAXUD >::Encode(instr); break;
            case I_PMAXUW:              encoder::Opcode$< I_PMAXUW >::Encode(instr); break;
            case I_PMINSB:              encoder::Opcode$< I_PMINSB >::Encode(instr); break;
            case I_PMINSD:              encoder::Opcode$< I_PMINSD >::Encode(instr); break;
            case I_PMINUD:              encoder::Opcode$< I_PMINUD >::Encode(instr); break;
            case I_PMINUW:              encoder::Opcode$< I_PMINUW >::Encode(instr); break;
            case I_PMOVSXBD:            encoder::Opcode$< I_PMOVSXBD >::Encode(instr); break;
            case I_PMOVSXBQ:            encoder::Opcode$< I_PMOVSXBQ >::Encode(instr); break;
            case I_PMOVSXBW:            encoder::Opcode$< I_PMOVSXBW >::Encode(instr); break;
            case I_PMOVSXDQ:            encoder::Opcode$< I_PMOVSXDQ >::Encode(instr); break;
            case I_PMOVSXWD:            encoder::Opcode$< I_PMOVSXWD >::Encode(instr); break;
            case I_PMOVSXWQ:            encoder::Opcode$< I_PMOVSXWQ >::Encode(instr); break;
            case I_PMOVZXBD:            encoder::Opcode$< I_PMOVZXBD >::Encode(instr); break;
            case I_PMOVZXBQ:            encoder::Opcode$< I_PMOVZXBQ >::Encode(instr); break;
            case I_PMOVZXBW:            encoder::Opcode$< I_PMOVZXBW >::Encode(instr); break;
            case I_PMOVZXDQ:            encoder::Opcode$< I_PMOVZXDQ >::Encode(instr); break;
            case I_PMOVZXWD:            encoder::Opcode$< I_PMOVZXWD >::Encode(instr); break;
            case I_PMOVZXWQ:            encoder::Opcode$< I_PMOVZXWQ >::Encode(instr); break;
            case I_PMULDQ:              encoder::Opcode$< I_PMULDQ >::Encode(instr); break;
            case I_PMULHRW:             encoder::Opcode$< I_PMULHRW >::Encode(instr); break;
            case I_PMULLD:              encoder::Opcode$< I_PMULLD >::Encode(instr); break;
            case I_POP:                 encoder::Opcode$< I_POP >::Encode(instr); break;
            case I_POPAW:               encoder::Opcode$< I_POPAW >::Encode(instr); break;
            case I_POPAL:               encoder::Opcode$< I_POPAL >::Encode(instr); break;
            case I_POPCNT:              encoder::Opcode$< I_POPCNT >::Encode(instr); break;
            case I_POPF:                encoder::Opcode$< I_POPF >::Encode(instr); break;
            case I_POPFD:               encoder::Opcode$< I_POPFD >::Encode(instr); break;
            case I_POPFQ:               encoder::Opcode$< I_POPFQ >::Encode(instr); break;
            case I_PREFETCH:            encoder::Opcode$< I_PREFETCH >::Encode(instr); break;
            case I_PREFETCHNTA:         encoder::Opcode$< I_PREFETCHNTA >::Encode(instr); break;
            case I_PREFETCHT0:          encoder::Opcode$< I_PREFETCHT0 >::Encode(instr); break;
            case I_PREFETCHT1:          encoder::Opcode$< I_PREFETCHT1 >::Encode(instr); break;
            case I_PREFETCHT2:          encoder::Opcode$< I_PREFETCHT2 >::Encode(instr); break;
            case I_PREFETCHW:           encoder::Opcode$< I_PREFETCHW >::Encode(instr); break;
            case I_PSHUFD:              encoder::Opcode$< I_PSHUFD >::Encode(instr); break;
            case I_PSHUFHW:             encoder::Opcode$< I_PSHUFHW >::Encode(instr); break;
            case I_PSHUFLW:             encoder::Opcode$< I_PSHUFLW >::Encode(instr); break;
            case I_PSLLDQ:              encoder::Opcode$< I_PSLLDQ >::Encode(instr); break;
            case I_PSRLDQ:              encoder::Opcode$< I_PSRLDQ >::Encode(instr); break;
            case I_PSWAPD:              encoder::Opcode$< I_PSWAPD >::Encode(instr); break;
            case I_PTEST:               encoder::Opcode$< I_PTEST >::Encode(instr); break;
            case I_PUNPCKHQDQ:          encoder::Opcode$< I_PUNPCKHQDQ >::Encode(instr); break;
            case I_PUNPCKLQDQ:          encoder::Opcode$< I_PUNPCKLQDQ >::Encode(instr); break;
            case I_PUSH:                encoder::Opcode$< I_PUSH >::Encode(instr); break;
            case I_PUSHAW:              encoder::Opcode$< I_PUSHAW >::Encode(instr); break;
            case I_PUSHAL:              encoder::Opcode$< I_PUSHAL >::Encode(instr); break;
            case I_PUSHF:               encoder::Opcode$< I_PUSHF >::Encode(instr); break;
            case I_PUSHFD:              encoder::Opcode$< I_PUSHFD >::Encode(instr); break;
            case I_PUSHFQ:              encoder::Opcode$< I_PUSHFQ >::Encode(instr); break;
            case I_RCL:                 encoder::Opcode$< I_RCL >::Encode(instr); break;
            case I_RCPPS:               encoder::Opcode$< I_RCPPS >::Encode(instr); break;
            case I_RCPSS:               encoder::Opcode$< I_RCPSS >::Encode(instr); break;
            case I_RCR:                 encoder::Opcode$< I_RCR >::Encode(instr); break;
            case I_RDFSBASE:            encoder::Opcode$< I_RDFSBASE >::Encode(instr); break;
            case I_RDGSBASE:            encoder::Opcode$< I_RDGSBASE >::Encode(instr); break;
            case I_RDMSR:               encoder::Opcode$< I_RDMSR >::Encode(instr); break;
            case I_RDPMC:               encoder::Opcode$< I_RDPMC >::Encode(instr); break;
            case I_RDRAND:              encoder::Opcode$< I_RDRAND >::Encode(instr); break;
            case I_RDSEED:              encoder::Opcode$< I_RDSEED >::Encode(instr); break;
            case I_RDTSC:               encoder::Opcode$< I_RDTSC >::Encode(instr); break;
            case I_RDTSCP:              encoder::Opcode$< I_RDTSCP >::Encode(instr); break;
            case I_REPNE:               encoder::Opcode$< I_REPNE >::Encode(instr); break;
            case I_REP:                 encoder::Opcode$< I_REP >::Encode(instr); break;
            case I_ROL:                 encoder::Opcode$< I_ROL >::Encode(instr); break;
            case I_ROR:                 encoder::Opcode$< I_ROR >::Encode(instr); break;
            case I_RORX:                encoder::Opcode$< I_RORX >::Encode(instr); break;
            case I_ROUNDPD:             encoder::Opcode$< I_ROUNDPD >::Encode(instr); break;
            case I_ROUNDPS:             encoder::Opcode$< I_ROUNDPS >::Encode(instr); break;
            case I_ROUNDSD:             encoder::Opcode$< I_ROUNDSD >::Encode(instr); break;
            case I_ROUNDSS:             encoder::Opcode$< I_ROUNDSS >::Encode(instr); break;
            case I_RSM:                 encoder::Opcode$< I_RSM >::Encode(instr); break;
            case I_RSQRTPS:             encoder::Opcode$< I_RSQRTPS >::Encode(instr); break;
            case I_RSQRTSS:             encoder::Opcode$< I_RSQRTSS >::Encode(instr); break;
            case I_SAHF:                encoder::Opcode$< I_SAHF >::Encode(instr); break;
            case I_SAL:                 encoder::Opcode$< I_SAL >::Encode(instr); break;
            case I_SALC:                encoder::Opcode$< I_SALC >::Encode(instr); break;
            case I_SAR:                 encoder::Opcode$< I_SAR >::Encode(instr); break;
            case I_SARX:                encoder::Opcode$< I_SARX >::Encode(instr); break;
            case I_SBB:                 encoder::Opcode$< I_SBB >::Encode(instr); break;
            case I_SCASB:               encoder::Opcode$< I_SCASB >::Encode(instr); break;
            case I_SCASD:               encoder::Opcode$< I_SCASD >::Encode(instr); break;
            case I_SCASQ:               encoder::Opcode$< I_SCASQ >::Encode(instr); break;
            case I_SCASW:               encoder::Opcode$< I_SCASW >::Encode(instr); break;
            case I_SETcc:               encoder::Opcode$< I_SETcc >::Encode(instr); break;
            case I_SFENCE:              encoder::Opcode$< I_SFENCE >::Encode(instr); break;
            case I_SGDT:                encoder::Opcode$< I_SGDT >::Encode(instr); break;
            case I_SHA1MSG1:            encoder::Opcode$< I_SHA1MSG1 >::Encode(instr); break;
            case I_SHA1MSG2:            encoder::Opcode$< I_SHA1MSG2 >::Encode(instr); break;
            case I_SHA1NEXTE:           encoder::Opcode$< I_SHA1NEXTE >::Encode(instr); break;
            case I_SHA1RNDS4:           encoder::Opcode$< I_SHA1RNDS4 >::Encode(instr); break;
            case I_SHA256MSG1:          encoder::Opcode$< I_SHA256MSG1 >::Encode(instr); break;
            case I_SHA256MSG2:          encoder::Opcode$< I_SHA256MSG2 >::Encode(instr); break;
            case I_SHA256RNDS2:         encoder::Opcode$< I_SHA256RNDS2 >::Encode(instr); break;
            case I_SHL:                 encoder::Opcode$< I_SHL >::Encode(instr); break;
            case I_SHLD:                encoder::Opcode$< I_SHLD >::Encode(instr); break;
            case I_SHLX:                encoder::Opcode$< I_SHLX >::Encode(instr); break;
            case I_SHR:                 encoder::Opcode$< I_SHR >::Encode(instr); break;
            case I_SHRD:                encoder::Opcode$< I_SHRD >::Encode(instr); break;
            case I_SHRX:                encoder::Opcode$< I_SHRX >::Encode(instr); break;
            case I_SHUFPD:              encoder::Opcode$< I_SHUFPD >::Encode(instr); break;
            case I_SHUFPS:              encoder::Opcode$< I_SHUFPS >::Encode(instr); break;
            case I_SIDT:                encoder::Opcode$< I_SIDT >::Encode(instr); break;
            case I_FSIN:                encoder::Opcode$< I_FSIN >::Encode(instr); break;
            case I_SKINIT:              encoder::Opcode$< I_SKINIT >::Encode(instr); break;
            case I_SLDT:                encoder::Opcode$< I_SLDT >::Encode(instr); break;
            case I_SMSW:                encoder::Opcode$< I_SMSW >::Encode(instr); break;
            case I_SQRTPD:              encoder::Opcode$< I_SQRTPD >::Encode(instr); break;
            case I_SQRTPS:              encoder::Opcode$< I_SQRTPS >::Encode(instr); break;
            case I_SQRTSD:              encoder::Opcode$< I_SQRTSD >::Encode(instr); break;
            case I_SQRTSS:              encoder::Opcode$< I_SQRTSS >::Encode(instr); break;
            case I_FSQRT:               encoder::Opcode$< I_FSQRT >::Encode(instr); break;
            case I_STAC:                encoder::Opcode$< I_STAC >::Encode(instr); break;
            case I_STC:                 encoder::Opcode$< I_STC >::Encode(instr); break;
            case I_STD:                 encoder::Opcode$< I_STD >::Encode(instr); break;
            case I_STGI:                encoder::Opcode$< I_STGI >::Encode(instr); break;
            case I_STI:                 encoder::Opcode$< I_STI >::Encode(instr); break;
            case I_STMXCSR:             encoder::Opcode$< I_STMXCSR >::Encode(instr); break;
            case I_STOSB:               encoder::Opcode$< I_STOSB >::Encode(instr); break;
            case I_STOSD:               encoder::Opcode$< I_STOSD >::Encode(instr); break;
            case I_STOSQ:               encoder::Opcode$< I_STOSQ >::Encode(instr); break;
            case I_STOSW:               encoder::Opcode$< I_STOSW >::Encode(instr); break;
            case I_STR:                 encoder::Opcode$< I_STR >::Encode(instr); break;
            case I_FST:                 encoder::Opcode$< I_FST >::Encode(instr); break;
            case I_FSTP:                encoder::Opcode$< I_FSTP >::Encode(instr); break;
            case I_FSTPNCE:             encoder::Opcode$< I_FSTPNCE >::Encode(instr); break;
            case I_SUBPD:               encoder::Opcode$< I_SUBPD >::Encode(instr); break;
            case I_SUBPS:               encoder::Opcode$< I_SUBPS >::Encode(instr); break;
            case I_FSUBR:               encoder::Opcode$< I_FSUBR >::Encode(instr); break;
            case I_FISUBR:              encoder::Opcode$< I_FISUBR >::Encode(instr); break;
            case I_FSUBRP:              encoder::Opcode$< I_FSUBRP >::Encode(instr); break;
            case I_SUBSD:               encoder::Opcode$< I_SUBSD >::Encode(instr); break;
            case I_SUBSS:               encoder::Opcode$< I_SUBSS >::Encode(instr); break;
            case I_FSUB:                encoder::Opcode$< I_FSUB >::Encode(instr); break;
            case I_FISUB:               encoder::Opcode$< I_FISUB >::Encode(instr); break;
            case I_FSUBP:               encoder::Opcode$< I_FSUBP >::Encode(instr); break;
            case I_SWAPGS:              encoder::Opcode$< I_SWAPGS >::Encode(instr); break;
            case I_SYSCALL:             encoder::Opcode$< I_SYSCALL >::Encode(instr); break;
            case I_SYSENTER:            encoder::Opcode$< I_SYSENTER >::Encode(instr); break;
            case I_SYSEXIT:             encoder::Opcode$< I_SYSEXIT >::Encode(instr); break;
            case I_SYSRET:              encoder::Opcode$< I_SYSRET >::Encode(instr); break;
            case I_T1MSKC:              encoder::Opcode$< I_T1MSKC >::Encode(instr); break;
            case I_TEST:                encoder::Opcode$< I_TEST >::Encode(instr); break;
            case I_UD2:                 encoder::Opcode$< I_UD2 >::Encode(instr); break;
            case I_FTST:                encoder::Opcode$< I_FTST >::Encode(instr); break;
            case I_TZCNT:               encoder::Opcode$< I_TZCNT >::Encode(instr); break;
            case I_TZMSK:               encoder::Opcode$< I_TZMSK >::Encode(instr); break;
            case I_FUCOMPI:             encoder::Opcode$< I_FUCOMPI >::Encode(instr); break;
            case I_FUCOMI:              encoder::Opcode$< I_FUCOMI >::Encode(instr); break;
            case I_FUCOMPP:             encoder::Opcode$< I_FUCOMPP >::Encode(instr); break;
            case I_FUCOMP:              encoder::Opcode$< I_FUCOMP >::Encode(instr); break;
            case I_FUCOM:               encoder::Opcode$< I_FUCOM >::Encode(instr); break;
            case I_UD2B:                encoder::Opcode$< I_UD2B >::Encode(instr); break;
            case I_UNPCKHPD:            encoder::Opcode$< I_UNPCKHPD >::Encode(instr); break;
            case I_UNPCKHPS:            encoder::Opcode$< I_UNPCKHPS >::Encode(instr); break;
            case I_UNPCKLPD:            encoder::Opcode$< I_UNPCKLPD >::Encode(instr); break;
            case I_UNPCKLPS:            encoder::Opcode$< I_UNPCKLPS >::Encode(instr); break;
            case I_VADDPD:              encoder::Opcode$< I_VADDPD >::Encode(instr); break;
            case I_VADDPS:              encoder::Opcode$< I_VADDPS >::Encode(instr); break;
            case I_VADDSD:              encoder::Opcode$< I_VADDSD >::Encode(instr); break;
            case I_VADDSS:              encoder::Opcode$< I_VADDSS >::Encode(instr); break;
            case I_VADDSUBPD:           encoder::Opcode$< I_VADDSUBPD >::Encode(instr); break;
            case I_VADDSUBPS:           encoder::Opcode$< I_VADDSUBPS >::Encode(instr); break;
            case I_VAESDECLAST:         encoder::Opcode$< I_VAESDECLAST >::Encode(instr); break;
            case I_VAESDEC:             encoder::Opcode$< I_VAESDEC >::Encode(instr); break;
            case I_VAESENCLAST:         encoder::Opcode$< I_VAESENCLAST >::Encode(instr); break;
            case I_VAESENC:             encoder::Opcode$< I_VAESENC >::Encode(instr); break;
            case I_VAESIMC:             encoder::Opcode$< I_VAESIMC >::Encode(instr); break;
            case I_VAESKEYGENASSIST:    encoder::Opcode$< I_VAESKEYGENASSIST >::Encode(instr); break;
            case I_VALIGND:             encoder::Opcode$< I_VALIGND >::Encode(instr); break;
            case I_VALIGNQ:             encoder::Opcode$< I_VALIGNQ >::Encode(instr); break;
            case I_VANDNPD:             encoder::Opcode$< I_VANDNPD >::Encode(instr); break;
            case I_VANDNPS:             encoder::Opcode$< I_VANDNPS >::Encode(instr); break;
            case I_VANDPD:              encoder::Opcode$< I_VANDPD >::Encode(instr); break;
            case I_VANDPS:              encoder::Opcode$< I_VANDPS >::Encode(instr); break;
            case I_VBLENDMPD:           encoder::Opcode$< I_VBLENDMPD >::Encode(instr); break;
            case I_VBLENDMPS:           encoder::Opcode$< I_VBLENDMPS >::Encode(instr); break;
            case I_VBLENDPD:            encoder::Opcode$< I_VBLENDPD >::Encode(instr); break;
            case I_VBLENDPS:            encoder::Opcode$< I_VBLENDPS >::Encode(instr); break;
            case I_VBLENDVPD:           encoder::Opcode$< I_VBLENDVPD >::Encode(instr); break;
            case I_VBLENDVPS:           encoder::Opcode$< I_VBLENDVPS >::Encode(instr); break;
            case I_VBROADCASTF128:      encoder::Opcode$< I_VBROADCASTF128 >::Encode(instr); break;
            case I_VBROADCASTI128:      encoder::Opcode$< I_VBROADCASTI128 >::Encode(instr); break;
            case I_VBROADCASTI32X4:     encoder::Opcode$< I_VBROADCASTI32X4 >::Encode(instr); break;
            case I_VBROADCASTI64X4:     encoder::Opcode$< I_VBROADCASTI64X4 >::Encode(instr); break;
            case I_VBROADCASTSD:        encoder::Opcode$< I_VBROADCASTSD >::Encode(instr); break;
            case I_VBROADCASTSS:        encoder::Opcode$< I_VBROADCASTSS >::Encode(instr); break;
            case I_VCMPPD:              encoder::Opcode$< I_VCMPPD >::Encode(instr); break;
            case I_VCMPPS:              encoder::Opcode$< I_VCMPPS >::Encode(instr); break;
            case I_VCMPSD:              encoder::Opcode$< I_VCMPSD >::Encode(instr); break;
            case I_VCMPSS:              encoder::Opcode$< I_VCMPSS >::Encode(instr); break;
            case I_VCVTDQ2PD:           encoder::Opcode$< I_VCVTDQ2PD >::Encode(instr); break;
            case I_VCVTDQ2PS:           encoder::Opcode$< I_VCVTDQ2PS >::Encode(instr); break;
            case I_VCVTPD2DQX:          encoder::Opcode$< I_VCVTPD2DQX >::Encode(instr); break;
            case I_VCVTPD2DQ:           encoder::Opcode$< I_VCVTPD2DQ >::Encode(instr); break;
            case I_VCVTPD2PSX:          encoder::Opcode$< I_VCVTPD2PSX >::Encode(instr); break;
            case I_VCVTPD2PS:           encoder::Opcode$< I_VCVTPD2PS >::Encode(instr); break;
            case I_VCVTPD2UDQ:          encoder::Opcode$< I_VCVTPD2UDQ >::Encode(instr); break;
            case I_VCVTPH2PS:           encoder::Opcode$< I_VCVTPH2PS >::Encode(instr); break;
            case I_VCVTPS2DQ:           encoder::Opcode$< I_VCVTPS2DQ >::Encode(instr); break;
            case I_VCVTPS2PD:           encoder::Opcode$< I_VCVTPS2PD >::Encode(instr); break;
            case I_VCVTPS2PH:           encoder::Opcode$< I_VCVTPS2PH >::Encode(instr); break;
            case I_VCVTPS2UDQ:          encoder::Opcode$< I_VCVTPS2UDQ >::Encode(instr); break;
            case I_VCVTSD2SI:           encoder::Opcode$< I_VCVTSD2SI >::Encode(instr); break;
            case I_VCVTSD2USI:          encoder::Opcode$< I_VCVTSD2USI >::Encode(instr); break;
            case I_VCVTSS2SI:           encoder::Opcode$< I_VCVTSS2SI >::Encode(instr); break;
            case I_VCVTSS2USI:          encoder::Opcode$< I_VCVTSS2USI >::Encode(instr); break;
            case I_VCVTTPD2DQX:         encoder::Opcode$< I_VCVTTPD2DQX >::Encode(instr); break;
            case I_VCVTTPD2DQ:          encoder::Opcode$< I_VCVTTPD2DQ >::Encode(instr); break;
            case I_VCVTTPD2UDQ:         encoder::Opcode$< I_VCVTTPD2UDQ >::Encode(instr); break;
            case I_VCVTTPS2DQ:          encoder::Opcode$< I_VCVTTPS2DQ >::Encode(instr); break;
            case I_VCVTTPS2UDQ:         encoder::Opcode$< I_VCVTTPS2UDQ >::Encode(instr); break;
            case I_VCVTUDQ2PD:          encoder::Opcode$< I_VCVTUDQ2PD >::Encode(instr); break;
            case I_VCVTUDQ2PS:          encoder::Opcode$< I_VCVTUDQ2PS >::Encode(instr); break;
            case I_VDIVPD:              encoder::Opcode$< I_VDIVPD >::Encode(instr); break;
            case I_VDIVPS:              encoder::Opcode$< I_VDIVPS >::Encode(instr); break;
            case I_VDIVSD:              encoder::Opcode$< I_VDIVSD >::Encode(instr); break;
            case I_VDIVSS:              encoder::Opcode$< I_VDIVSS >::Encode(instr); break;
            case I_VDPPD:               encoder::Opcode$< I_VDPPD >::Encode(instr); break;
            case I_VDPPS:               encoder::Opcode$< I_VDPPS >::Encode(instr); break;
            case I_VERR:                encoder::Opcode$< I_VERR >::Encode(instr); break;
            case I_VERW:                encoder::Opcode$< I_VERW >::Encode(instr); break;
            case I_VEXTRACTF128:        encoder::Opcode$< I_VEXTRACTF128 >::Encode(instr); break;
            case I_VEXTRACTF32X4:       encoder::Opcode$< I_VEXTRACTF32X4 >::Encode(instr); break;
            case I_VEXTRACTF64X4:       encoder::Opcode$< I_VEXTRACTF64X4 >::Encode(instr); break;
            case I_VEXTRACTI128:        encoder::Opcode$< I_VEXTRACTI128 >::Encode(instr); break;
            case I_VEXTRACTI32X4:       encoder::Opcode$< I_VEXTRACTI32X4 >::Encode(instr); break;
            case I_VEXTRACTI64X4:       encoder::Opcode$< I_VEXTRACTI64X4 >::Encode(instr); break;
            case I_VEXTRACTPS:          encoder::Opcode$< I_VEXTRACTPS >::Encode(instr); break;
            case I_VFMADD132PD:         encoder::Opcode$< I_VFMADD132PD >::Encode(instr); break;
            case I_VFMADD132PS:         encoder::Opcode$< I_VFMADD132PS >::Encode(instr); break;
            case I_VFMADD213PD:         encoder::Opcode$< I_VFMADD213PD >::Encode(instr); break;
            case I_VFMADD213PS:         encoder::Opcode$< I_VFMADD213PS >::Encode(instr); break;
            case I_VFMADDPD:            encoder::Opcode$< I_VFMADDPD >::Encode(instr); break;
            case I_VFMADD231PD:         encoder::Opcode$< I_VFMADD231PD >::Encode(instr); break;
            case I_VFMADDPS:            encoder::Opcode$< I_VFMADDPS >::Encode(instr); break;
            case I_VFMADD231PS:         encoder::Opcode$< I_VFMADD231PS >::Encode(instr); break;
            case I_VFMADDSD:            encoder::Opcode$< I_VFMADDSD >::Encode(instr); break;
            case I_VFMADD213SD:         encoder::Opcode$< I_VFMADD213SD >::Encode(instr); break;
            case I_VFMADD132SD:         encoder::Opcode$< I_VFMADD132SD >::Encode(instr); break;
            case I_VFMADD231SD:         encoder::Opcode$< I_VFMADD231SD >::Encode(instr); break;
            case I_VFMADDSS:            encoder::Opcode$< I_VFMADDSS >::Encode(instr); break;
            case I_VFMADD213SS:         encoder::Opcode$< I_VFMADD213SS >::Encode(instr); break;
            case I_VFMADD132SS:         encoder::Opcode$< I_VFMADD132SS >::Encode(instr); break;
            case I_VFMADD231SS:         encoder::Opcode$< I_VFMADD231SS >::Encode(instr); break;
            case I_VFMADDSUB132PD:      encoder::Opcode$< I_VFMADDSUB132PD >::Encode(instr); break;
            case I_VFMADDSUB132PS:      encoder::Opcode$< I_VFMADDSUB132PS >::Encode(instr); break;
            case I_VFMADDSUB213PD:      encoder::Opcode$< I_VFMADDSUB213PD >::Encode(instr); break;
            case I_VFMADDSUB213PS:      encoder::Opcode$< I_VFMADDSUB213PS >::Encode(instr); break;
            case I_VFMADDSUBPD:         encoder::Opcode$< I_VFMADDSUBPD >::Encode(instr); break;
            case I_VFMADDSUB231PD:      encoder::Opcode$< I_VFMADDSUB231PD >::Encode(instr); break;
            case I_VFMADDSUBPS:         encoder::Opcode$< I_VFMADDSUBPS >::Encode(instr); break;
            case I_VFMADDSUB231PS:      encoder::Opcode$< I_VFMADDSUB231PS >::Encode(instr); break;
            case I_VFMSUB132PD:         encoder::Opcode$< I_VFMSUB132PD >::Encode(instr); break;
            case I_VFMSUB132PS:         encoder::Opcode$< I_VFMSUB132PS >::Encode(instr); break;
            case I_VFMSUB213PD:         encoder::Opcode$< I_VFMSUB213PD >::Encode(instr); break;
            case I_VFMSUB213PS:         encoder::Opcode$< I_VFMSUB213PS >::Encode(instr); break;
            case I_VFMSUBADD132PD:      encoder::Opcode$< I_VFMSUBADD132PD >::Encode(instr); break;
            case I_VFMSUBADD132PS:      encoder::Opcode$< I_VFMSUBADD132PS >::Encode(instr); break;
            case I_VFMSUBADD213PD:      encoder::Opcode$< I_VFMSUBADD213PD >::Encode(instr); break;
            case I_VFMSUBADD213PS:      encoder::Opcode$< I_VFMSUBADD213PS >::Encode(instr); break;
            case I_VFMSUBADDPD:         encoder::Opcode$< I_VFMSUBADDPD >::Encode(instr); break;
            case I_VFMSUBADD231PD:      encoder::Opcode$< I_VFMSUBADD231PD >::Encode(instr); break;
            case I_VFMSUBADDPS:         encoder::Opcode$< I_VFMSUBADDPS >::Encode(instr); break;
            case I_VFMSUBADD231PS:      encoder::Opcode$< I_VFMSUBADD231PS >::Encode(instr); break;
            case I_VFMSUBPD:            encoder::Opcode$< I_VFMSUBPD >::Encode(instr); break;
            case I_VFMSUB231PD:         encoder::Opcode$< I_VFMSUB231PD >::Encode(instr); break;
            case I_VFMSUBPS:            encoder::Opcode$< I_VFMSUBPS >::Encode(instr); break;
            case I_VFMSUB231PS:         encoder::Opcode$< I_VFMSUB231PS >::Encode(instr); break;
            case I_VFMSUBSD:            encoder::Opcode$< I_VFMSUBSD >::Encode(instr); break;
            case I_VFMSUB213SD:         encoder::Opcode$< I_VFMSUB213SD >::Encode(instr); break;
            case I_VFMSUB132SD:         encoder::Opcode$< I_VFMSUB132SD >::Encode(instr); break;
            case I_VFMSUB231SD:         encoder::Opcode$< I_VFMSUB231SD >::Encode(instr); break;
            case I_VFMSUBSS:            encoder::Opcode$< I_VFMSUBSS >::Encode(instr); break;
            case I_VFMSUB213SS:         encoder::Opcode$< I_VFMSUB213SS >::Encode(instr); break;
            case I_VFMSUB132SS:         encoder::Opcode$< I_VFMSUB132SS >::Encode(instr); break;
            case I_VFMSUB231SS:         encoder::Opcode$< I_VFMSUB231SS >::Encode(instr); break;
            case I_VFNMADD132PD:        encoder::Opcode$< I_VFNMADD132PD >::Encode(instr); break;
            case I_VFNMADD132PS:        encoder::Opcode$< I_VFNMADD132PS >::Encode(instr); break;
            case I_VFNMADD213PD:        encoder::Opcode$< I_VFNMADD213PD >::Encode(instr); break;
            case I_VFNMADD213PS:        encoder::Opcode$< I_VFNMADD213PS >::Encode(instr); break;
            case I_VFNMADDPD:           encoder::Opcode$< I_VFNMADDPD >::Encode(instr); break;
            case I_VFNMADD231PD:        encoder::Opcode$< I_VFNMADD231PD >::Encode(instr); break;
            case I_VFNMADDPS:           encoder::Opcode$< I_VFNMADDPS >::Encode(instr); break;
            case I_VFNMADD231PS:        encoder::Opcode$< I_VFNMADD231PS >::Encode(instr); break;
            case I_VFNMADDSD:           encoder::Opcode$< I_VFNMADDSD >::Encode(instr); break;
            case I_VFNMADD213SD:        encoder::Opcode$< I_VFNMADD213SD >::Encode(instr); break;
            case I_VFNMADD132SD:        encoder::Opcode$< I_VFNMADD132SD >::Encode(instr); break;
            case I_VFNMADD231SD:        encoder::Opcode$< I_VFNMADD231SD >::Encode(instr); break;
            case I_VFNMADDSS:           encoder::Opcode$< I_VFNMADDSS >::Encode(instr); break;
            case I_VFNMADD213SS:        encoder::Opcode$< I_VFNMADD213SS >::Encode(instr); break;
            case I_VFNMADD132SS:        encoder::Opcode$< I_VFNMADD132SS >::Encode(instr); break;
            case I_VFNMADD231SS:        encoder::Opcode$< I_VFNMADD231SS >::Encode(instr); break;
            case I_VFNMSUB132PD:        encoder::Opcode$< I_VFNMSUB132PD >::Encode(instr); break;
            case I_VFNMSUB132PS:        encoder::Opcode$< I_VFNMSUB132PS >::Encode(instr); break;
            case I_VFNMSUB213PD:        encoder::Opcode$< I_VFNMSUB213PD >::Encode(instr); break;
            case I_VFNMSUB213PS:        encoder::Opcode$< I_VFNMSUB213PS >::Encode(instr); break;
            case I_VFNMSUBPD:           encoder::Opcode$< I_VFNMSUBPD >::Encode(instr); break;
            case I_VFNMSUB231PD:        encoder::Opcode$< I_VFNMSUB231PD >::Encode(instr); break;
            case I_VFNMSUBPS:           encoder::Opcode$< I_VFNMSUBPS >::Encode(instr); break;
            case I_VFNMSUB231PS:        encoder::Opcode$< I_VFNMSUB231PS >::Encode(instr); break;
            case I_VFNMSUBSD:           encoder::Opcode$< I_VFNMSUBSD >::Encode(instr); break;
            case I_VFNMSUB213SD:        encoder::Opcode$< I_VFNMSUB213SD >::Encode(instr); break;
            case I_VFNMSUB132SD:        encoder::Opcode$< I_VFNMSUB132SD >::Encode(instr); break;
            case I_VFNMSUB231SD:        encoder::Opcode$< I_VFNMSUB231SD >::Encode(instr); break;
            case I_VFNMSUBSS:           encoder::Opcode$< I_VFNMSUBSS >::Encode(instr); break;
            case I_VFNMSUB213SS:        encoder::Opcode$< I_VFNMSUB213SS >::Encode(instr); break;
            case I_VFNMSUB132SS:        encoder::Opcode$< I_VFNMSUB132SS >::Encode(instr); break;
            case I_VFNMSUB231SS:        encoder::Opcode$< I_VFNMSUB231SS >::Encode(instr); break;
            case I_VFRCZPD:             encoder::Opcode$< I_VFRCZPD >::Encode(instr); break;
            case I_VFRCZPS:             encoder::Opcode$< I_VFRCZPS >::Encode(instr); break;
            case I_VFRCZSD:             encoder::Opcode$< I_VFRCZSD >::Encode(instr); break;
            case I_VFRCZSS:             encoder::Opcode$< I_VFRCZSS >::Encode(instr); break;
            case I_VORPD:               encoder::Opcode$< I_VORPD >::Encode(instr); break;
            case I_VORPS:               encoder::Opcode$< I_VORPS >::Encode(instr); break;
            case I_VXORPD:              encoder::Opcode$< I_VXORPD >::Encode(instr); break;
            case I_VXORPS:              encoder::Opcode$< I_VXORPS >::Encode(instr); break;
            case I_VGATHERDPD:          encoder::Opcode$< I_VGATHERDPD >::Encode(instr); break;
            case I_VGATHERDPS:          encoder::Opcode$< I_VGATHERDPS >::Encode(instr); break;
            case I_VGATHERPF0DPD:       encoder::Opcode$< I_VGATHERPF0DPD >::Encode(instr); break;
            case I_VGATHERPF0DPS:       encoder::Opcode$< I_VGATHERPF0DPS >::Encode(instr); break;
            case I_VGATHERPF0QPD:       encoder::Opcode$< I_VGATHERPF0QPD >::Encode(instr); break;
            case I_VGATHERPF0QPS:       encoder::Opcode$< I_VGATHERPF0QPS >::Encode(instr); break;
            case I_VGATHERPF1DPD:       encoder::Opcode$< I_VGATHERPF1DPD >::Encode(instr); break;
            case I_VGATHERPF1DPS:       encoder::Opcode$< I_VGATHERPF1DPS >::Encode(instr); break;
            case I_VGATHERPF1QPD:       encoder::Opcode$< I_VGATHERPF1QPD >::Encode(instr); break;
            case I_VGATHERPF1QPS:       encoder::Opcode$< I_VGATHERPF1QPS >::Encode(instr); break;
            case I_VGATHERQPD:          encoder::Opcode$< I_VGATHERQPD >::Encode(instr); break;
            case I_VGATHERQPS:          encoder::Opcode$< I_VGATHERQPS >::Encode(instr); break;
            case I_VHADDPD:             encoder::Opcode$< I_VHADDPD >::Encode(instr); break;
            case I_VHADDPS:             encoder::Opcode$< I_VHADDPS >::Encode(instr); break;
            case I_VHSUBPD:             encoder::Opcode$< I_VHSUBPD >::Encode(instr); break;
            case I_VHSUBPS:             encoder::Opcode$< I_VHSUBPS >::Encode(instr); break;
            case I_VINSERTF128:         encoder::Opcode$< I_VINSERTF128 >::Encode(instr); break;
            case I_VINSERTF32X4:        encoder::Opcode$< I_VINSERTF32X4 >::Encode(instr); break;
            case I_VINSERTF64X4:        encoder::Opcode$< I_VINSERTF64X4 >::Encode(instr); break;
            case I_VINSERTI128:         encoder::Opcode$< I_VINSERTI128 >::Encode(instr); break;
            case I_VINSERTI32X4:        encoder::Opcode$< I_VINSERTI32X4 >::Encode(instr); break;
            case I_VINSERTI64X4:        encoder::Opcode$< I_VINSERTI64X4 >::Encode(instr); break;
            case I_VINSERTPS:           encoder::Opcode$< I_VINSERTPS >::Encode(instr); break;
            case I_VLDDQU:              encoder::Opcode$< I_VLDDQU >::Encode(instr); break;
            case I_VLDMXCSR:            encoder::Opcode$< I_VLDMXCSR >::Encode(instr); break;
            case I_VMASKMOVDQU:         encoder::Opcode$< I_VMASKMOVDQU >::Encode(instr); break;
            case I_VMASKMOVPD:          encoder::Opcode$< I_VMASKMOVPD >::Encode(instr); break;
            case I_VMASKMOVPS:          encoder::Opcode$< I_VMASKMOVPS >::Encode(instr); break;
            case I_VMAXPD:              encoder::Opcode$< I_VMAXPD >::Encode(instr); break;
            case I_VMAXPS:              encoder::Opcode$< I_VMAXPS >::Encode(instr); break;
            case I_VMAXSD:              encoder::Opcode$< I_VMAXSD >::Encode(instr); break;
            case I_VMAXSS:              encoder::Opcode$< I_VMAXSS >::Encode(instr); break;
            case I_VMCALL:              encoder::Opcode$< I_VMCALL >::Encode(instr); break;
            case I_VMCLEAR:             encoder::Opcode$< I_VMCLEAR >::Encode(instr); break;
            case I_VMFUNC:              encoder::Opcode$< I_VMFUNC >::Encode(instr); break;
            case I_VMINPD:              encoder::Opcode$< I_VMINPD >::Encode(instr); break;
            case I_VMINPS:              encoder::Opcode$< I_VMINPS >::Encode(instr); break;
            case I_VMINSD:              encoder::Opcode$< I_VMINSD >::Encode(instr); break;
            case I_VMINSS:              encoder::Opcode$< I_VMINSS >::Encode(instr); break;
            case I_VMLAUNCH:            encoder::Opcode$< I_VMLAUNCH >::Encode(instr); break;
            case I_VMLOAD:              encoder::Opcode$< I_VMLOAD >::Encode(instr); break;
            case I_VMMCALL:             encoder::Opcode$< I_VMMCALL >::Encode(instr); break;
            case I_VMOVQ:               encoder::Opcode$< I_VMOVQ >::Encode(instr); break;
            case I_VMOVDDUP:            encoder::Opcode$< I_VMOVDDUP >::Encode(instr); break;
            case I_VMOVD:               encoder::Opcode$< I_VMOVD >::Encode(instr); break;
            case I_VMOVDQA32:           encoder::Opcode$< I_VMOVDQA32 >::Encode(instr); break;
            case I_VMOVDQA64:           encoder::Opcode$< I_VMOVDQA64 >::Encode(instr); break;
            case I_VMOVDQA:             encoder::Opcode$< I_VMOVDQA >::Encode(instr); break;
            case I_VMOVDQU16:           encoder::Opcode$< I_VMOVDQU16 >::Encode(instr); break;
            case I_VMOVDQU32:           encoder::Opcode$< I_VMOVDQU32 >::Encode(instr); break;
            case I_VMOVDQU64:           encoder::Opcode$< I_VMOVDQU64 >::Encode(instr); break;
            case I_VMOVDQU8:            encoder::Opcode$< I_VMOVDQU8 >::Encode(instr); break;
            case I_VMOVDQU:             encoder::Opcode$< I_VMOVDQU >::Encode(instr); break;
            case I_VMOVHLPS:            encoder::Opcode$< I_VMOVHLPS >::Encode(instr); break;
            case I_VMOVHPD:             encoder::Opcode$< I_VMOVHPD >::Encode(instr); break;
            case I_VMOVHPS:             encoder::Opcode$< I_VMOVHPS >::Encode(instr); break;
            case I_VMOVLHPS:            encoder::Opcode$< I_VMOVLHPS >::Encode(instr); break;
            case I_VMOVLPD:             encoder::Opcode$< I_VMOVLPD >::Encode(instr); break;
            case I_VMOVLPS:             encoder::Opcode$< I_VMOVLPS >::Encode(instr); break;
            case I_VMOVMSKPD:           encoder::Opcode$< I_VMOVMSKPD >::Encode(instr); break;
            case I_VMOVMSKPS:           encoder::Opcode$< I_VMOVMSKPS >::Encode(instr); break;
            case I_VMOVNTDQA:           encoder::Opcode$< I_VMOVNTDQA >::Encode(instr); break;
            case I_VMOVNTDQ:            encoder::Opcode$< I_VMOVNTDQ >::Encode(instr); break;
            case I_VMOVNTPD:            encoder::Opcode$< I_VMOVNTPD >::Encode(instr); break;
            case I_VMOVNTPS:            encoder::Opcode$< I_VMOVNTPS >::Encode(instr); break;
            case I_VMOVSD:              encoder::Opcode$< I_VMOVSD >::Encode(instr); break;
            case I_VMOVSHDUP:           encoder::Opcode$< I_VMOVSHDUP >::Encode(instr); break;
            case I_VMOVSLDUP:           encoder::Opcode$< I_VMOVSLDUP >::Encode(instr); break;
            case I_VMOVSS:              encoder::Opcode$< I_VMOVSS >::Encode(instr); break;
            case I_VMOVUPD:             encoder::Opcode$< I_VMOVUPD >::Encode(instr); break;
            case I_VMOVUPS:             encoder::Opcode$< I_VMOVUPS >::Encode(instr); break;
            case I_VMPSADBW:            encoder::Opcode$< I_VMPSADBW >::Encode(instr); break;
            case I_VMPTRLD:             encoder::Opcode$< I_VMPTRLD >::Encode(instr); break;
            case I_VMPTRST:             encoder::Opcode$< I_VMPTRST >::Encode(instr); break;
            case I_VMREAD:              encoder::Opcode$< I_VMREAD >::Encode(instr); break;
            case I_VMRESUME:            encoder::Opcode$< I_VMRESUME >::Encode(instr); break;
            case I_VMRUN:               encoder::Opcode$< I_VMRUN >::Encode(instr); break;
            case I_VMSAVE:              encoder::Opcode$< I_VMSAVE >::Encode(instr); break;
            case I_VMULPD:              encoder::Opcode$< I_VMULPD >::Encode(instr); break;
            case I_VMULPS:              encoder::Opcode$< I_VMULPS >::Encode(instr); break;
            case I_VMULSD:              encoder::Opcode$< I_VMULSD >::Encode(instr); break;
            case I_VMULSS:              encoder::Opcode$< I_VMULSS >::Encode(instr); break;
            case I_VMWRITE:             encoder::Opcode$< I_VMWRITE >::Encode(instr); break;
            case I_VMXOFF:              encoder::Opcode$< I_VMXOFF >::Encode(instr); break;
            case I_VMXON:               encoder::Opcode$< I_VMXON >::Encode(instr); break;
            case I_VPABSB:              encoder::Opcode$< I_VPABSB >::Encode(instr); break;
            case I_VPABSD:              encoder::Opcode$< I_VPABSD >::Encode(instr); break;
            case I_VPABSQ:              encoder::Opcode$< I_VPABSQ >::Encode(instr); break;
            case I_VPABSW:              encoder::Opcode$< I_VPABSW >::Encode(instr); break;
            case I_VPACKSSDW:           encoder::Opcode$< I_VPACKSSDW >::Encode(instr); break;
            case I_VPACKSSWB:           encoder::Opcode$< I_VPACKSSWB >::Encode(instr); break;
            case I_VPACKUSDW:           encoder::Opcode$< I_VPACKUSDW >::Encode(instr); break;
            case I_VPACKUSWB:           encoder::Opcode$< I_VPACKUSWB >::Encode(instr); break;
            case I_VPADDB:              encoder::Opcode$< I_VPADDB >::Encode(instr); break;
            case I_VPADDD:              encoder::Opcode$< I_VPADDD >::Encode(instr); break;
            case I_VPADDQ:              encoder::Opcode$< I_VPADDQ >::Encode(instr); break;
            case I_VPADDSB:             encoder::Opcode$< I_VPADDSB >::Encode(instr); break;
            case I_VPADDSW:             encoder::Opcode$< I_VPADDSW >::Encode(instr); break;
            case I_VPADDUSB:            encoder::Opcode$< I_VPADDUSB >::Encode(instr); break;
            case I_VPADDUSW:            encoder::Opcode$< I_VPADDUSW >::Encode(instr); break;
            case I_VPADDW:              encoder::Opcode$< I_VPADDW >::Encode(instr); break;
            case I_VPALIGNR:            encoder::Opcode$< I_VPALIGNR >::Encode(instr); break;
            case I_VPANDD:              encoder::Opcode$< I_VPANDD >::Encode(instr); break;
            case I_VPANDND:             encoder::Opcode$< I_VPANDND >::Encode(instr); break;
            case I_VPANDNQ:             encoder::Opcode$< I_VPANDNQ >::Encode(instr); break;
            case I_VPANDN:              encoder::Opcode$< I_VPANDN >::Encode(instr); break;
            case I_VPANDQ:              encoder::Opcode$< I_VPANDQ >::Encode(instr); break;
            case I_VPAND:               encoder::Opcode$< I_VPAND >::Encode(instr); break;
            case I_VPAVGB:              encoder::Opcode$< I_VPAVGB >::Encode(instr); break;
            case I_VPAVGW:              encoder::Opcode$< I_VPAVGW >::Encode(instr); break;
            case I_VPBLENDD:            encoder::Opcode$< I_VPBLENDD >::Encode(instr); break;
            case I_VPBLENDMD:           encoder::Opcode$< I_VPBLENDMD >::Encode(instr); break;
            case I_VPBLENDMQ:           encoder::Opcode$< I_VPBLENDMQ >::Encode(instr); break;
            case I_VPBLENDVB:           encoder::Opcode$< I_VPBLENDVB >::Encode(instr); break;
            case I_VPBLENDW:            encoder::Opcode$< I_VPBLENDW >::Encode(instr); break;
            case I_VPBROADCASTB:        encoder::Opcode$< I_VPBROADCASTB >::Encode(instr); break;
            case I_VPBROADCASTD:        encoder::Opcode$< I_VPBROADCASTD >::Encode(instr); break;
            case I_VPBROADCASTMB2Q:     encoder::Opcode$< I_VPBROADCASTMB2Q >::Encode(instr); break;
            case I_VPBROADCASTMW2D:     encoder::Opcode$< I_VPBROADCASTMW2D >::Encode(instr); break;
            case I_VPBROADCASTQ:        encoder::Opcode$< I_VPBROADCASTQ >::Encode(instr); break;
            case I_VPBROADCASTW:        encoder::Opcode$< I_VPBROADCASTW >::Encode(instr); break;
            case I_VPCLMULQDQ:          encoder::Opcode$< I_VPCLMULQDQ >::Encode(instr); break;
            case I_VPCMOV:              encoder::Opcode$< I_VPCMOV >::Encode(instr); break;
            case I_VPCMP:               encoder::Opcode$< I_VPCMP >::Encode(instr); break;
            case I_VPCMPD:              encoder::Opcode$< I_VPCMPD >::Encode(instr); break;
            case I_VPCMPEQB:            encoder::Opcode$< I_VPCMPEQB >::Encode(instr); break;
            case I_VPCMPEQD:            encoder::Opcode$< I_VPCMPEQD >::Encode(instr); break;
            case I_VPCMPEQQ:            encoder::Opcode$< I_VPCMPEQQ >::Encode(instr); break;
            case I_VPCMPEQW:            encoder::Opcode$< I_VPCMPEQW >::Encode(instr); break;
            case I_VPCMPESTRI:          encoder::Opcode$< I_VPCMPESTRI >::Encode(instr); break;
            case I_VPCMPESTRM:          encoder::Opcode$< I_VPCMPESTRM >::Encode(instr); break;
            case I_VPCMPGTB:            encoder::Opcode$< I_VPCMPGTB >::Encode(instr); break;
            case I_VPCMPGTD:            encoder::Opcode$< I_VPCMPGTD >::Encode(instr); break;
            case I_VPCMPGTQ:            encoder::Opcode$< I_VPCMPGTQ >::Encode(instr); break;
            case I_VPCMPGTW:            encoder::Opcode$< I_VPCMPGTW >::Encode(instr); break;
            case I_VPCMPISTRI:          encoder::Opcode$< I_VPCMPISTRI >::Encode(instr); break;
            case I_VPCMPISTRM:          encoder::Opcode$< I_VPCMPISTRM >::Encode(instr); break;
            case I_VPCMPQ:              encoder::Opcode$< I_VPCMPQ >::Encode(instr); break;
            case I_VPCMPUD:             encoder::Opcode$< I_VPCMPUD >::Encode(instr); break;
            case I_VPCMPUQ:             encoder::Opcode$< I_VPCMPUQ >::Encode(instr); break;
            case I_VPCOMB:              encoder::Opcode$< I_VPCOMB >::Encode(instr); break;
            case I_VPCOMD:              encoder::Opcode$< I_VPCOMD >::Encode(instr); break;
            case I_VPCOMQ:              encoder::Opcode$< I_VPCOMQ >::Encode(instr); break;
            case I_VPCOMUB:             encoder::Opcode$< I_VPCOMUB >::Encode(instr); break;
            case I_VPCOMUD:             encoder::Opcode$< I_VPCOMUD >::Encode(instr); break;
            case I_VPCOMUQ:             encoder::Opcode$< I_VPCOMUQ >::Encode(instr); break;
            case I_VPCOMUW:             encoder::Opcode$< I_VPCOMUW >::Encode(instr); break;
            case I_VPCOMW:              encoder::Opcode$< I_VPCOMW >::Encode(instr); break;
            case I_VPCONFLICTD:         encoder::Opcode$< I_VPCONFLICTD >::Encode(instr); break;
            case I_VPCONFLICTQ:         encoder::Opcode$< I_VPCONFLICTQ >::Encode(instr); break;
            case I_VPERM2F128:          encoder::Opcode$< I_VPERM2F128 >::Encode(instr); break;
            case I_VPERM2I128:          encoder::Opcode$< I_VPERM2I128 >::Encode(instr); break;
            case I_VPERMD:              encoder::Opcode$< I_VPERMD >::Encode(instr); break;
            case I_VPERMI2D:            encoder::Opcode$< I_VPERMI2D >::Encode(instr); break;
            case I_VPERMI2PD:           encoder::Opcode$< I_VPERMI2PD >::Encode(instr); break;
            case I_VPERMI2PS:           encoder::Opcode$< I_VPERMI2PS >::Encode(instr); break;
            case I_VPERMI2Q:            encoder::Opcode$< I_VPERMI2Q >::Encode(instr); break;
            case I_VPERMIL2PD:          encoder::Opcode$< I_VPERMIL2PD >::Encode(instr); break;
            case I_VPERMIL2PS:          encoder::Opcode$< I_VPERMIL2PS >::Encode(instr); break;
            case I_VPERMILPD:           encoder::Opcode$< I_VPERMILPD >::Encode(instr); break;
            case I_VPERMILPS:           encoder::Opcode$< I_VPERMILPS >::Encode(instr); break;
            case I_VPERMPD:             encoder::Opcode$< I_VPERMPD >::Encode(instr); break;
            case I_VPERMPS:             encoder::Opcode$< I_VPERMPS >::Encode(instr); break;
            case I_VPERMQ:              encoder::Opcode$< I_VPERMQ >::Encode(instr); break;
            case I_VPERMT2D:            encoder::Opcode$< I_VPERMT2D >::Encode(instr); break;
            case I_VPERMT2PD:           encoder::Opcode$< I_VPERMT2PD >::Encode(instr); break;
            case I_VPERMT2PS:           encoder::Opcode$< I_VPERMT2PS >::Encode(instr); break;
            case I_VPERMT2Q:            encoder::Opcode$< I_VPERMT2Q >::Encode(instr); break;
            case I_VPEXTRB:             encoder::Opcode$< I_VPEXTRB >::Encode(instr); break;
            case I_VPEXTRD:             encoder::Opcode$< I_VPEXTRD >::Encode(instr); break;
            case I_VPEXTRQ:             encoder::Opcode$< I_VPEXTRQ >::Encode(instr); break;
            case I_VPEXTRW:             encoder::Opcode$< I_VPEXTRW >::Encode(instr); break;
            case I_VPGATHERDD:          encoder::Opcode$< I_VPGATHERDD >::Encode(instr); break;
            case I_VPGATHERDQ:          encoder::Opcode$< I_VPGATHERDQ >::Encode(instr); break;
            case I_VPGATHERQD:          encoder::Opcode$< I_VPGATHERQD >::Encode(instr); break;
            case I_VPGATHERQQ:          encoder::Opcode$< I_VPGATHERQQ >::Encode(instr); break;
            case I_VPHADDBD:            encoder::Opcode$< I_VPHADDBD >::Encode(instr); break;
            case I_VPHADDBQ:            encoder::Opcode$< I_VPHADDBQ >::Encode(instr); break;
            case I_VPHADDBW:            encoder::Opcode$< I_VPHADDBW >::Encode(instr); break;
            case I_VPHADDDQ:            encoder::Opcode$< I_VPHADDDQ >::Encode(instr); break;
            case I_VPHADDD:             encoder::Opcode$< I_VPHADDD >::Encode(instr); break;
            case I_VPHADDSW:            encoder::Opcode$< I_VPHADDSW >::Encode(instr); break;
            case I_VPHADDUBD:           encoder::Opcode$< I_VPHADDUBD >::Encode(instr); break;
            case I_VPHADDUBQ:           encoder::Opcode$< I_VPHADDUBQ >::Encode(instr); break;
            case I_VPHADDUBW:           encoder::Opcode$< I_VPHADDUBW >::Encode(instr); break;
            case I_VPHADDUDQ:           encoder::Opcode$< I_VPHADDUDQ >::Encode(instr); break;
            case I_VPHADDUWD:           encoder::Opcode$< I_VPHADDUWD >::Encode(instr); break;
            case I_VPHADDUWQ:           encoder::Opcode$< I_VPHADDUWQ >::Encode(instr); break;
            case I_VPHADDWD:            encoder::Opcode$< I_VPHADDWD >::Encode(instr); break;
            case I_VPHADDWQ:            encoder::Opcode$< I_VPHADDWQ >::Encode(instr); break;
            case I_VPHADDW:             encoder::Opcode$< I_VPHADDW >::Encode(instr); break;
            case I_VPHMINPOSUW:         encoder::Opcode$< I_VPHMINPOSUW >::Encode(instr); break;
            case I_VPHSUBBW:            encoder::Opcode$< I_VPHSUBBW >::Encode(instr); break;
            case I_VPHSUBDQ:            encoder::Opcode$< I_VPHSUBDQ >::Encode(instr); break;
            case I_VPHSUBD:             encoder::Opcode$< I_VPHSUBD >::Encode(instr); break;
            case I_VPHSUBSW:            encoder::Opcode$< I_VPHSUBSW >::Encode(instr); break;
            case I_VPHSUBWD:            encoder::Opcode$< I_VPHSUBWD >::Encode(instr); break;
            case I_VPHSUBW:             encoder::Opcode$< I_VPHSUBW >::Encode(instr); break;
            case I_VPINSRB:             encoder::Opcode$< I_VPINSRB >::Encode(instr); break;
            case I_VPINSRD:             encoder::Opcode$< I_VPINSRD >::Encode(instr); break;
            case I_VPINSRQ:             encoder::Opcode$< I_VPINSRQ >::Encode(instr); break;
            case I_VPINSRW:             encoder::Opcode$< I_VPINSRW >::Encode(instr); break;
            case I_VPLZCNTD:            encoder::Opcode$< I_VPLZCNTD >::Encode(instr); break;
            case I_VPLZCNTQ:            encoder::Opcode$< I_VPLZCNTQ >::Encode(instr); break;
            case I_VPMACSDD:            encoder::Opcode$< I_VPMACSDD >::Encode(instr); break;
            case I_VPMACSDQH:           encoder::Opcode$< I_VPMACSDQH >::Encode(instr); break;
            case I_VPMACSDQL:           encoder::Opcode$< I_VPMACSDQL >::Encode(instr); break;
            case I_VPMACSSDD:           encoder::Opcode$< I_VPMACSSDD >::Encode(instr); break;
            case I_VPMACSSDQH:          encoder::Opcode$< I_VPMACSSDQH >::Encode(instr); break;
            case I_VPMACSSDQL:          encoder::Opcode$< I_VPMACSSDQL >::Encode(instr); break;
            case I_VPMACSSWD:           encoder::Opcode$< I_VPMACSSWD >::Encode(instr); break;
            case I_VPMACSSWW:           encoder::Opcode$< I_VPMACSSWW >::Encode(instr); break;
            case I_VPMACSWD:            encoder::Opcode$< I_VPMACSWD >::Encode(instr); break;
            case I_VPMACSWW:            encoder::Opcode$< I_VPMACSWW >::Encode(instr); break;
            case I_VPMADCSSWD:          encoder::Opcode$< I_VPMADCSSWD >::Encode(instr); break;
            case I_VPMADCSWD:           encoder::Opcode$< I_VPMADCSWD >::Encode(instr); break;
            case I_VPMADDUBSW:          encoder::Opcode$< I_VPMADDUBSW >::Encode(instr); break;
            case I_VPMADDWD:            encoder::Opcode$< I_VPMADDWD >::Encode(instr); break;
            case I_VPMASKMOVD:          encoder::Opcode$< I_VPMASKMOVD >::Encode(instr); break;
            case I_VPMASKMOVQ:          encoder::Opcode$< I_VPMASKMOVQ >::Encode(instr); break;
            case I_VPMAXSB:             encoder::Opcode$< I_VPMAXSB >::Encode(instr); break;
            case I_VPMAXSD:             encoder::Opcode$< I_VPMAXSD >::Encode(instr); break;
            case I_VPMAXSQ:             encoder::Opcode$< I_VPMAXSQ >::Encode(instr); break;
            case I_VPMAXSW:             encoder::Opcode$< I_VPMAXSW >::Encode(instr); break;
            case I_VPMAXUB:             encoder::Opcode$< I_VPMAXUB >::Encode(instr); break;
            case I_VPMAXUD:             encoder::Opcode$< I_VPMAXUD >::Encode(instr); break;
            case I_VPMAXUQ:             encoder::Opcode$< I_VPMAXUQ >::Encode(instr); break;
            case I_VPMAXUW:             encoder::Opcode$< I_VPMAXUW >::Encode(instr); break;
            case I_VPMINSB:             encoder::Opcode$< I_VPMINSB >::Encode(instr); break;
            case I_VPMINSD:             encoder::Opcode$< I_VPMINSD >::Encode(instr); break;
            case I_VPMINSQ:             encoder::Opcode$< I_VPMINSQ >::Encode(instr); break;
            case I_VPMINSW:             encoder::Opcode$< I_VPMINSW >::Encode(instr); break;
            case I_VPMINUB:             encoder::Opcode$< I_VPMINUB >::Encode(instr); break;
            case I_VPMINUD:             encoder::Opcode$< I_VPMINUD >::Encode(instr); break;
            case I_VPMINUQ:             encoder::Opcode$< I_VPMINUQ >::Encode(instr); break;
            case I_VPMINUW:             encoder::Opcode$< I_VPMINUW >::Encode(instr); break;
            case I_VPMOVDB:             encoder::Opcode$< I_VPMOVDB >::Encode(instr); break;
            case I_VPMOVDW:             encoder::Opcode$< I_VPMOVDW >::Encode(instr); break;
            case I_VPMOVMSKB:           encoder::Opcode$< I_VPMOVMSKB >::Encode(instr); break;
            case I_VPMOVQB:             encoder::Opcode$< I_VPMOVQB >::Encode(instr); break;
            case I_VPMOVQD:             encoder::Opcode$< I_VPMOVQD >::Encode(instr); break;
            case I_VPMOVQW:             encoder::Opcode$< I_VPMOVQW >::Encode(instr); break;
            case I_VPMOVSDB:            encoder::Opcode$< I_VPMOVSDB >::Encode(instr); break;
            case I_VPMOVSDW:            encoder::Opcode$< I_VPMOVSDW >::Encode(instr); break;
            case I_VPMOVSQB:            encoder::Opcode$< I_VPMOVSQB >::Encode(instr); break;
            case I_VPMOVSQD:            encoder::Opcode$< I_VPMOVSQD >::Encode(instr); break;
            case I_VPMOVSQW:            encoder::Opcode$< I_VPMOVSQW >::Encode(instr); break;
            case I_VPMOVSXBD:           encoder::Opcode$< I_VPMOVSXBD >::Encode(instr); break;
            case I_VPMOVSXBQ:           encoder::Opcode$< I_VPMOVSXBQ >::Encode(instr); break;
            case I_VPMOVSXBW:           encoder::Opcode$< I_VPMOVSXBW >::Encode(instr); break;
            case I_VPMOVSXDQ:           encoder::Opcode$< I_VPMOVSXDQ >::Encode(instr); break;
            case I_VPMOVSXWD:           encoder::Opcode$< I_VPMOVSXWD >::Encode(instr); break;
            case I_VPMOVSXWQ:           encoder::Opcode$< I_VPMOVSXWQ >::Encode(instr); break;
            case I_VPMOVUSDB:           encoder::Opcode$< I_VPMOVUSDB >::Encode(instr); break;
            case I_VPMOVUSDW:           encoder::Opcode$< I_VPMOVUSDW >::Encode(instr); break;
            case I_VPMOVUSQB:           encoder::Opcode$< I_VPMOVUSQB >::Encode(instr); break;
            case I_VPMOVUSQD:           encoder::Opcode$< I_VPMOVUSQD >::Encode(instr); break;
            case I_VPMOVUSQW:           encoder::Opcode$< I_VPMOVUSQW >::Encode(instr); break;
            case I_VPMOVZXBD:           encoder::Opcode$< I_VPMOVZXBD >::Encode(instr); break;
            case I_VPMOVZXBQ:           encoder::Opcode$< I_VPMOVZXBQ >::Encode(instr); break;
            case I_VPMOVZXBW:           encoder::Opcode$< I_VPMOVZXBW >::Encode(instr); break;
            case I_VPMOVZXDQ:           encoder::Opcode$< I_VPMOVZXDQ >::Encode(instr); break;
            case I_VPMOVZXWD:           encoder::Opcode$< I_VPMOVZXWD >::Encode(instr); break;
            case I_VPMOVZXWQ:           encoder::Opcode$< I_VPMOVZXWQ >::Encode(instr); break;
            case I_VPMULDQ:             encoder::Opcode$< I_VPMULDQ >::Encode(instr); break;
            case I_VPMULHRSW:           encoder::Opcode$< I_VPMULHRSW >::Encode(instr); break;
            case I_VPMULHUW:            encoder::Opcode$< I_VPMULHUW >::Encode(instr); break;
            case I_VPMULHW:             encoder::Opcode$< I_VPMULHW >::Encode(instr); break;
            case I_VPMULLD:             encoder::Opcode$< I_VPMULLD >::Encode(instr); break;
            case I_VPMULLW:             encoder::Opcode$< I_VPMULLW >::Encode(instr); break;
            case I_VPMULUDQ:            encoder::Opcode$< I_VPMULUDQ >::Encode(instr); break;
            case I_VPORD:               encoder::Opcode$< I_VPORD >::Encode(instr); break;
            case I_VPORQ:               encoder::Opcode$< I_VPORQ >::Encode(instr); break;
            case I_VPOR:                encoder::Opcode$< I_VPOR >::Encode(instr); break;
            case I_VPPERM:              encoder::Opcode$< I_VPPERM >::Encode(instr); break;
            case I_VPROTB:              encoder::Opcode$< I_VPROTB >::Encode(instr); break;
            case I_VPROTD:              encoder::Opcode$< I_VPROTD >::Encode(instr); break;
            case I_VPROTQ:              encoder::Opcode$< I_VPROTQ >::Encode(instr); break;
            case I_VPROTW:              encoder::Opcode$< I_VPROTW >::Encode(instr); break;
            case I_VPSADBW:             encoder::Opcode$< I_VPSADBW >::Encode(instr); break;
            case I_VPSCATTERDD:         encoder::Opcode$< I_VPSCATTERDD >::Encode(instr); break;
            case I_VPSCATTERDQ:         encoder::Opcode$< I_VPSCATTERDQ >::Encode(instr); break;
            case I_VPSCATTERQD:         encoder::Opcode$< I_VPSCATTERQD >::Encode(instr); break;
            case I_VPSCATTERQQ:         encoder::Opcode$< I_VPSCATTERQQ >::Encode(instr); break;
            case I_VPSHAB:              encoder::Opcode$< I_VPSHAB >::Encode(instr); break;
            case I_VPSHAD:              encoder::Opcode$< I_VPSHAD >::Encode(instr); break;
            case I_VPSHAQ:              encoder::Opcode$< I_VPSHAQ >::Encode(instr); break;
            case I_VPSHAW:              encoder::Opcode$< I_VPSHAW >::Encode(instr); break;
            case I_VPSHLB:              encoder::Opcode$< I_VPSHLB >::Encode(instr); break;
            case I_VPSHLD:              encoder::Opcode$< I_VPSHLD >::Encode(instr); break;
            case I_VPSHLQ:              encoder::Opcode$< I_VPSHLQ >::Encode(instr); break;
            case I_VPSHLW:              encoder::Opcode$< I_VPSHLW >::Encode(instr); break;
            case I_VPSHUFB:             encoder::Opcode$< I_VPSHUFB >::Encode(instr); break;
            case I_VPSHUFD:             encoder::Opcode$< I_VPSHUFD >::Encode(instr); break;
            case I_VPSHUFHW:            encoder::Opcode$< I_VPSHUFHW >::Encode(instr); break;
            case I_VPSHUFLW:            encoder::Opcode$< I_VPSHUFLW >::Encode(instr); break;
            case I_VPSIGNB:             encoder::Opcode$< I_VPSIGNB >::Encode(instr); break;
            case I_VPSIGND:             encoder::Opcode$< I_VPSIGND >::Encode(instr); break;
            case I_VPSIGNW:             encoder::Opcode$< I_VPSIGNW >::Encode(instr); break;
            case I_VPSLLDQ:             encoder::Opcode$< I_VPSLLDQ >::Encode(instr); break;
            case I_VPSLLD:              encoder::Opcode$< I_VPSLLD >::Encode(instr); break;
            case I_VPSLLQ:              encoder::Opcode$< I_VPSLLQ >::Encode(instr); break;
            case I_VPSLLVD:             encoder::Opcode$< I_VPSLLVD >::Encode(instr); break;
            case I_VPSLLVQ:             encoder::Opcode$< I_VPSLLVQ >::Encode(instr); break;
            case I_VPSLLW:              encoder::Opcode$< I_VPSLLW >::Encode(instr); break;
            case I_VPSRAD:              encoder::Opcode$< I_VPSRAD >::Encode(instr); break;
            case I_VPSRAQ:              encoder::Opcode$< I_VPSRAQ >::Encode(instr); break;
            case I_VPSRAVD:             encoder::Opcode$< I_VPSRAVD >::Encode(instr); break;
            case I_VPSRAVQ:             encoder::Opcode$< I_VPSRAVQ >::Encode(instr); break;
            case I_VPSRAW:              encoder::Opcode$< I_VPSRAW >::Encode(instr); break;
            case I_VPSRLDQ:             encoder::Opcode$< I_VPSRLDQ >::Encode(instr); break;
            case I_VPSRLD:              encoder::Opcode$< I_VPSRLD >::Encode(instr); break;
            case I_VPSRLQ:              encoder::Opcode$< I_VPSRLQ >::Encode(instr); break;
            case I_VPSRLVD:             encoder::Opcode$< I_VPSRLVD >::Encode(instr); break;
            case I_VPSRLVQ:             encoder::Opcode$< I_VPSRLVQ >::Encode(instr); break;
            case I_VPSRLW:              encoder::Opcode$< I_VPSRLW >::Encode(instr); break;
            case I_VPSUBB:              encoder::Opcode$< I_VPSUBB >::Encode(instr); break;
            case I_VPSUBD:              encoder::Opcode$< I_VPSUBD >::Encode(instr); break;
            case I_VPSUBQ:              encoder::Opcode$< I_VPSUBQ >::Encode(instr); break;
            case I_VPSUBSB:             encoder::Opcode$< I_VPSUBSB >::Encode(instr); break;
            case I_VPSUBSW:             encoder::Opcode$< I_VPSUBSW >::Encode(instr); break;
            case I_VPSUBUSB:            encoder::Opcode$< I_VPSUBUSB >::Encode(instr); break;
            case I_VPSUBUSW:            encoder::Opcode$< I_VPSUBUSW >::Encode(instr); break;
            case I_VPSUBW:              encoder::Opcode$< I_VPSUBW >::Encode(instr); break;
            case I_VPTESTMD:            encoder::Opcode$< I_VPTESTMD >::Encode(instr); break;
            case I_VPTESTMQ:            encoder::Opcode$< I_VPTESTMQ >::Encode(instr); break;
            case I_VPTESTNMD:           encoder::Opcode$< I_VPTESTNMD >::Encode(instr); break;
            case I_VPTESTNMQ:           encoder::Opcode$< I_VPTESTNMQ >::Encode(instr); break;
            case I_VPTEST:              encoder::Opcode$< I_VPTEST >::Encode(instr); break;
            case I_VPUNPCKHBW:          encoder::Opcode$< I_VPUNPCKHBW >::Encode(instr); break;
            case I_VPUNPCKHDQ:          encoder::Opcode$< I_VPUNPCKHDQ >::Encode(instr); break;
            case I_VPUNPCKHQDQ:         encoder::Opcode$< I_VPUNPCKHQDQ >::Encode(instr); break;
            case I_VPUNPCKHWD:          encoder::Opcode$< I_VPUNPCKHWD >::Encode(instr); break;
            case I_VPUNPCKLBW:          encoder::Opcode$< I_VPUNPCKLBW >::Encode(instr); break;
            case I_VPUNPCKLDQ:          encoder::Opcode$< I_VPUNPCKLDQ >::Encode(instr); break;
            case I_VPUNPCKLQDQ:         encoder::Opcode$< I_VPUNPCKLQDQ >::Encode(instr); break;
            case I_VPUNPCKLWD:          encoder::Opcode$< I_VPUNPCKLWD >::Encode(instr); break;
            case I_VPXORD:              encoder::Opcode$< I_VPXORD >::Encode(instr); break;
            case I_VPXORQ:              encoder::Opcode$< I_VPXORQ >::Encode(instr); break;
            case I_VPXOR:               encoder::Opcode$< I_VPXOR >::Encode(instr); break;
            case I_VRCP14PD:            encoder::Opcode$< I_VRCP14PD >::Encode(instr); break;
            case I_VRCP14PS:            encoder::Opcode$< I_VRCP14PS >::Encode(instr); break;
            case I_VRCP14SD:            encoder::Opcode$< I_VRCP14SD >::Encode(instr); break;
            case I_VRCP14SS:            encoder::Opcode$< I_VRCP14SS >::Encode(instr); break;
            case I_VRCP28PD:            encoder::Opcode$< I_VRCP28PD >::Encode(instr); break;
            case I_VRCP28PS:            encoder::Opcode$< I_VRCP28PS >::Encode(instr); break;
            case I_VRCP28SD:            encoder::Opcode$< I_VRCP28SD >::Encode(instr); break;
            case I_VRCP28SS:            encoder::Opcode$< I_VRCP28SS >::Encode(instr); break;
            case I_VRCPPS:              encoder::Opcode$< I_VRCPPS >::Encode(instr); break;
            case I_VRCPSS:              encoder::Opcode$< I_VRCPSS >::Encode(instr); break;
            case I_VRNDSCALEPD:         encoder::Opcode$< I_VRNDSCALEPD >::Encode(instr); break;
            case I_VRNDSCALEPS:         encoder::Opcode$< I_VRNDSCALEPS >::Encode(instr); break;
            case I_VRNDSCALESD:         encoder::Opcode$< I_VRNDSCALESD >::Encode(instr); break;
            case I_VRNDSCALESS:         encoder::Opcode$< I_VRNDSCALESS >::Encode(instr); break;
            case I_VROUNDPD:            encoder::Opcode$< I_VROUNDPD >::Encode(instr); break;
            case I_VROUNDPS:            encoder::Opcode$< I_VROUNDPS >::Encode(instr); break;
            case I_VROUNDSD:            encoder::Opcode$< I_VROUNDSD >::Encode(instr); break;
            case I_VROUNDSS:            encoder::Opcode$< I_VROUNDSS >::Encode(instr); break;
            case I_VRSQRT14PD:          encoder::Opcode$< I_VRSQRT14PD >::Encode(instr); break;
            case I_VRSQRT14PS:          encoder::Opcode$< I_VRSQRT14PS >::Encode(instr); break;
            case I_VRSQRT14SD:          encoder::Opcode$< I_VRSQRT14SD >::Encode(instr); break;
            case I_VRSQRT14SS:          encoder::Opcode$< I_VRSQRT14SS >::Encode(instr); break;
            case I_VRSQRT28PD:          encoder::Opcode$< I_VRSQRT28PD >::Encode(instr); break;
            case I_VRSQRT28PS:          encoder::Opcode$< I_VRSQRT28PS >::Encode(instr); break;
            case I_VRSQRT28SD:          encoder::Opcode$< I_VRSQRT28SD >::Encode(instr); break;
            case I_VRSQRT28SS:          encoder::Opcode$< I_VRSQRT28SS >::Encode(instr); break;
            case I_VRSQRTPS:            encoder::Opcode$< I_VRSQRTPS >::Encode(instr); break;
            case I_VRSQRTSS:            encoder::Opcode$< I_VRSQRTSS >::Encode(instr); break;
            case I_VSCATTERDPD:         encoder::Opcode$< I_VSCATTERDPD >::Encode(instr); break;
            case I_VSCATTERDPS:         encoder::Opcode$< I_VSCATTERDPS >::Encode(instr); break;
            case I_VSCATTERPF0DPD:      encoder::Opcode$< I_VSCATTERPF0DPD >::Encode(instr); break;
            case I_VSCATTERPF0DPS:      encoder::Opcode$< I_VSCATTERPF0DPS >::Encode(instr); break;
            case I_VSCATTERPF0QPD:      encoder::Opcode$< I_VSCATTERPF0QPD >::Encode(instr); break;
            case I_VSCATTERPF0QPS:      encoder::Opcode$< I_VSCATTERPF0QPS >::Encode(instr); break;
            case I_VSCATTERPF1DPD:      encoder::Opcode$< I_VSCATTERPF1DPD >::Encode(instr); break;
            case I_VSCATTERPF1DPS:      encoder::Opcode$< I_VSCATTERPF1DPS >::Encode(instr); break;
            case I_VSCATTERPF1QPD:      encoder::Opcode$< I_VSCATTERPF1QPD >::Encode(instr); break;
            case I_VSCATTERPF1QPS:      encoder::Opcode$< I_VSCATTERPF1QPS >::Encode(instr); break;
            case I_VSCATTERQPD:         encoder::Opcode$< I_VSCATTERQPD >::Encode(instr); break;
            case I_VSCATTERQPS:         encoder::Opcode$< I_VSCATTERQPS >::Encode(instr); break;
            case I_VSHUFPD:             encoder::Opcode$< I_VSHUFPD >::Encode(instr); break;
            case I_VSHUFPS:             encoder::Opcode$< I_VSHUFPS >::Encode(instr); break;
            case I_VSQRTPD:             encoder::Opcode$< I_VSQRTPD >::Encode(instr); break;
            case I_VSQRTPS:             encoder::Opcode$< I_VSQRTPS >::Encode(instr); break;
            case I_VSQRTSD:             encoder::Opcode$< I_VSQRTSD >::Encode(instr); break;
            case I_VSQRTSS:             encoder::Opcode$< I_VSQRTSS >::Encode(instr); break;
            case I_VSTMXCSR:            encoder::Opcode$< I_VSTMXCSR >::Encode(instr); break;
            case I_VSUBPD:              encoder::Opcode$< I_VSUBPD >::Encode(instr); break;
            case I_VSUBPS:              encoder::Opcode$< I_VSUBPS >::Encode(instr); break;
            case I_VSUBSD:              encoder::Opcode$< I_VSUBSD >::Encode(instr); break;
            case I_VSUBSS:              encoder::Opcode$< I_VSUBSS >::Encode(instr); break;
            case I_VTESTPD:             encoder::Opcode$< I_VTESTPD >::Encode(instr); break;
            case I_VTESTPS:             encoder::Opcode$< I_VTESTPS >::Encode(instr); break;
            case I_VUNPCKHPD:           encoder::Opcode$< I_VUNPCKHPD >::Encode(instr); break;
            case I_VUNPCKHPS:           encoder::Opcode$< I_VUNPCKHPS >::Encode(instr); break;
            case I_VUNPCKLPD:           encoder::Opcode$< I_VUNPCKLPD >::Encode(instr); break;
            case I_VUNPCKLPS:           encoder::Opcode$< I_VUNPCKLPS >::Encode(instr); break;
            case I_VZEROALL:            encoder::Opcode$< I_VZEROALL >::Encode(instr); break;
            case I_VZEROUPPER:          encoder::Opcode$< I_VZEROUPPER >::Encode(instr); break;
            case I_WAIT:                encoder::Opcode$< I_WAIT >::Encode(instr); break;
            case I_WBINVD:              encoder::Opcode$< I_WBINVD >::Encode(instr); break;
            case I_WRFSBASE:            encoder::Opcode$< I_WRFSBASE >::Encode(instr); break;
            case I_WRGSBASE:            encoder::Opcode$< I_WRGSBASE >::Encode(instr); break;
            case I_WRMSR:               encoder::Opcode$< I_WRMSR >::Encode(instr); break;
            case I_XABORT:              encoder::Opcode$< I_XABORT >::Encode(instr); break;
            case I_XACQUIRE:            encoder::Opcode$< I_XACQUIRE >::Encode(instr); break;
            case I_XBEGIN:              encoder::Opcode$< I_XBEGIN >::Encode(instr); break;
            case I_XCHG:                encoder::Opcode$< I_XCHG >::Encode(instr); break;
            case I_FXCH:                encoder::Opcode$< I_FXCH >::Encode(instr); break;
            case I_XCRYPTCBC:           encoder::Opcode$< I_XCRYPTCBC >::Encode(instr); break;
            case I_XCRYPTCFB:           encoder::Opcode$< I_XCRYPTCFB >::Encode(instr); break;
            case I_XCRYPTCTR:           encoder::Opcode$< I_XCRYPTCTR >::Encode(instr); break;
            case I_XCRYPTECB:           encoder::Opcode$< I_XCRYPTECB >::Encode(instr); break;
            case I_XCRYPTOFB:           encoder::Opcode$< I_XCRYPTOFB >::Encode(instr); break;
            case I_XEND:                encoder::Opcode$< I_XEND >::Encode(instr); break;
            case I_XGETBV:              encoder::Opcode$< I_XGETBV >::Encode(instr); break;
            case I_XLATB:               encoder::Opcode$< I_XLATB >::Encode(instr); break;
            case I_XRELEASE:            encoder::Opcode$< I_XRELEASE >::Encode(instr); break;
            case I_XRSTOR:              encoder::Opcode$< I_XRSTOR >::Encode(instr); break;
            case I_XRSTOR64:            encoder::Opcode$< I_XRSTOR64 >::Encode(instr); break;
            case I_XSAVE:               encoder::Opcode$< I_XSAVE >::Encode(instr); break;
            case I_XSAVE64:             encoder::Opcode$< I_XSAVE64 >::Encode(instr); break;
            case I_XSAVEOPT:            encoder::Opcode$< I_XSAVEOPT >::Encode(instr); break;
            case I_XSAVEOPT64:          encoder::Opcode$< I_XSAVEOPT64 >::Encode(instr); break;
            case I_XSETBV:              encoder::Opcode$< I_XSETBV >::Encode(instr); break;
            case I_XSHA1:               encoder::Opcode$< I_XSHA1 >::Encode(instr); break;
            case I_XSHA256:             encoder::Opcode$< I_XSHA256 >::Encode(instr); break;
            case I_XSTORE:              encoder::Opcode$< I_XSTORE >::Encode(instr); break;
            case I_XTEST:               encoder::Opcode$< I_XTEST >::Encode(instr); break;
            default:
                JITASM_ASSERT(0 && "unknown instruction");
            }
        }
    }
}
