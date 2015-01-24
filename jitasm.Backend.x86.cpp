#include "jitasm.x86.encoder.h"
#include "jitasm.Backend.x86.h"

namespace jitasm
{
    namespace x86
    {
        namespace encoder
        {
            // Group 8086+
            template<> struct Opcode$< I_AAA > : Opcode < I_AAA, 0x00000037, Gw < RW >, DummyRw< 0, AX >, i64 > {};

            template<> struct Opcode$< I_AAD > : Opcode < I_AAD, 0x000000D5, Gw_Ib < RW >, DummyRw< 0, AX >, i64 > {};

            template<> struct Opcode$< I_AAM > : Opcode < I_AAM, 0x000000D4, Gw_Ib < RW >, DummyRw< 0, AX >, i64 > {};

            template<> struct Opcode$< I_AAS > : Opcode < I_AAS, 0x0000003F, Gw < RW >, DummyRw< 0, AX >, i64 > {};

            template<> struct Opcode$< I_ADC > :
                Switch
                <
                /**/ Opcode < I_ADC, 0x00000012, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_ADC, 0x00000013, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_ADC, 0x00000013, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_ADC, 0x00000013, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_ADC, 0x00000010, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_ADC, 0x00000011, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_ADC, 0x00000011, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_ADC, 0x00000011, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_ADC, 0x00000014, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_ADC, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000015, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_ADC, 0x00000015, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_ADC, 0x00000015, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_ADC, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <2> >,
                /**/ Opcode < I_ADC, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <2> >
                > {};

            template<> struct Opcode$< I_ADD > :
                Switch
                <
                /**/ Opcode < I_ADD, 0x00000002, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_ADD, 0x00000003, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_ADD, 0x00000003, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_ADD, 0x00000003, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_ADD, 0x00000000, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_ADD, 0x00000001, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_ADD, 0x00000001, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_ADD, 0x00000001, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_ADD, 0x00000004, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_ADD, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000005, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_ADD, 0x00000005, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_ADD, 0x00000005, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_ADD, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <0> >,
                /**/ Opcode < I_ADD, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <0> >
                > {};

            template<> struct Opcode$< I_AND > :
                Switch
                <
                /**/ Opcode < I_AND, 0x00000022, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_AND, 0x00000023, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_AND, 0x00000023, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_AND, 0x00000023, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_AND, 0x00000020, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_AND, 0x00000021, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_AND, 0x00000021, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_AND, 0x00000021, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_AND, 0x00000024, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_AND, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000025, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_AND, 0x00000025, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_AND, 0x00000025, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_AND, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <4> >,
                /**/ Opcode < I_AND, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <4> >
                > {};

            template<> struct Opcode$< I_CALL > :
                Switch
                <
                /**/ Opcode < I_CALL, 0x000000E8, Jw, OSw >,
                /**/ Opcode < I_CALL, 0x000000E8, Jd, OSd >,
                /**/ Opcode < I_CALL, 0x000000FF, Ew < R >, OSw, Group5 <2> >,
                /**/ Opcode < I_CALL, 0x000000FF, Ed < R >, OSd, Group5 <2> >,
                /**/ Opcode < I_CALL, 0x000000FF, Eq < R >, OSq, Group5 <2> >
                > {};

            template<> struct Opcode$< I_CBW > : Opcode < I_CBW, 0x000000098, Gw < RW >, OSw, DummyRw< 0, AX > > {};

            template<> struct Opcode$< I_CLC > : Opcode < I_CLC, 0x0000000F8, None > {};

            template<> struct Opcode$< I_CLD > : Opcode < I_CLD, 0x0000000FC, None > {};

            template<> struct Opcode$< I_CLI > : Opcode < I_CLI, 0x0000000FA, None > {};

            template<> struct Opcode$< I_CMC > : Opcode < I_CMC, 0x0000000F5, None > {};

            template<> struct Opcode$< I_CMP > :
                Switch
                <
                /**/ Opcode < I_CMP, 0x0000003A, Gb_Eb  < R, R >, OSb             >,
                /**/ Opcode < I_CMP, 0x0000003B, Gw_Ew  < R, R >, OSw             >,
                /**/ Opcode < I_CMP, 0x0000003B, Gd_Ed  < R, R >, OSd             >,
                /**/ Opcode < I_CMP, 0x0000003B, Gq_Eq  < R, R >, OSq             >,
                /**/ Opcode < I_CMP, 0x00000038, Eb_Gb  < R, R >, OSb             >,
                /**/ Opcode < I_CMP, 0x00000039, Ew_Gw  < R, R >, OSw             >,
                /**/ Opcode < I_CMP, 0x00000039, Ed_Gd  < R, R >, OSd             >,
                /**/ Opcode < I_CMP, 0x00000039, Eq_Gq  < R, R >, OSq             >,
                /**/ Opcode < I_CMP, 0x0000003C, AL_Ib  < R    >                  >,
                /**/ Opcode < I_CMP, 0x00000080, Eb_Ib  < R    >, OSb, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000083, Ew_Ib  < R    >, OSw, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000083, Ed_Ib  < R    >, OSd, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000083, Eq_Ib  < R    >, OSq, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x0000003D, AX_Iw  < R    >, OSw             >,
                /**/ Opcode < I_CMP, 0x0000003D, EAX_Id < R    >, OSd             >,
                /**/ Opcode < I_CMP, 0x0000003D, RAX_Id < R    >, OSq             >,
                /**/ Opcode < I_CMP, 0x00000081, Ew_Iw  < R    >, OSw, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000081, Ed_Id  < R    >, OSd, Group1 <7> >,
                /**/ Opcode < I_CMP, 0x00000081, Eq_Id  < R    >, OSq, Group1 <7> >
                > {};

            template<> struct Opcode$< I_CMPS  > :
                Switch
                <
                /**/ Opcode < I_CMPS, 0x000000A6, Xb_Yb  < R, R >, OSb >,
                /**/ Opcode < I_CMPS, 0x000000A7, Xw_Yw  < R, R >, OSw >,
                /**/ Opcode < I_CMPS, 0x000000A7, Xd_Yd  < R, R >, OSd >,
                /**/ Opcode < I_CMPS, 0x000000A7, Xq_Yq  < R, R >, OSq >
                > {};

            template<> struct Opcode$< I_CWD > : Opcode < I_CWD, 0x00000099, Gw_Gw < RW, W >, DummyRw< 0, AX >, DummyRw< 1, DX >, OSw > {};

            template<> struct Opcode$< I_DAA > : Opcode < I_DAA, 0x00000027, Gw < RW >, DummyRw< 0, AX >, i64 > {};

            template<> struct Opcode$< I_DAS > : Opcode < I_DAS, 0x0000002F, Gw < RW >, DummyRw< 0, AX >, i64 > {};

            template<> struct Opcode$< I_DEC > :
                Switch
                <
                /**/ Opcode < I_DEC, 0x00000048, Zw < RW >, OSw, i64 >,
                /**/ Opcode < I_DEC, 0x00000048, Zd < RW >, OSd, i64 >,
                /**/ Opcode < I_DEC, 0x000000FE, Eb < RW >, OSb, Group4< 1 > >,
                /**/ Opcode < I_DEC, 0x000000FF, Ew < RW >, OSw, Group5< 1 > >,
                /**/ Opcode < I_DEC, 0x000000FF, Ed < RW >, OSd, Group5< 1 > >,
                /**/ Opcode < I_DEC, 0x000000FF, Eq < RW >, OSq, Group5< 1 > >
                > {};

            template<> struct Opcode$< I_DIV > :
                Switch
                <
                /**/ Opcode < I_DIV, 0x000000F6, Gw_Eb    < RW,     R >, DummyRw< 0, AX  >,                    OSb, Group3< 6 > >,
                /**/ Opcode < I_DIV, 0x000000F7, Gw_Gw_Ew < RW, RW, R >, DummyRw< 0, AX  >, DummyRw< 2, DX  >, OSw, Group3< 6 > >,
                /**/ Opcode < I_DIV, 0x000000F7, Gd_Gd_Ed < RW, RW, R >, DummyRd< 0, EAX >, DummyRd< 2, EDX >, OSd, Group3< 6 > >,
                /**/ Opcode < I_DIV, 0x000000F7, Gq_Gq_Eq < RW, RW, R >, DummyRq< 0, RAX >, DummyRq< 2, RDX >, OSq, Group3< 6 > >
                > {};

            template<> struct Opcode$< I_HLT > : Opcode < I_HLT, 0x000000F4, None > {};

            template<> struct Opcode$< I_IDIV > :
                Switch
                <
                /**/ Opcode < I_IDIV, 0x000000F6, Gw_Eb    < RW,     R >, DummyRw< 0, AX  >,                    OSb, Group3< 7 > >,
                /**/ Opcode < I_IDIV, 0x000000F7, Gw_Gw_Ew < RW, RW, R >, DummyRw< 0, AX  >, DummyRw< 2, DX  >, OSw, Group3< 7 > >,
                /**/ Opcode < I_IDIV, 0x000000F7, Gd_Gd_Ed < RW, RW, R >, DummyRd< 0, EAX >, DummyRd< 2, EDX >, OSd, Group3< 7 > >,
                /**/ Opcode < I_IDIV, 0x000000F7, Gq_Gq_Eq < RW, RW, R >, DummyRq< 0, RAX >, DummyRq< 2, RDX >, OSq, Group3< 7 > >
                > {};

            template<> struct Opcode$< I_IMUL > :
                Switch
                <
                /**/ Opcode < I_IMUL, 0x000000F6, Gw_Eb    < RW,     R >, DummyRw< 0, AX  >,                    OSb, Group3< 5 > >,
                /**/ Opcode < I_IMUL, 0x000000F7, Gw_Gw_Ew < RW, RW, R >, DummyRw< 0, AX  >, DummyRw< 2, DX  >, OSw, Group3< 5 > >,
                /**/ Opcode < I_IMUL, 0x000000F7, Gd_Gd_Ed < RW, RW, R >, DummyRd< 0, EAX >, DummyRd< 2, EDX >, OSd, Group3< 5 > >,
                /**/ Opcode < I_IMUL, 0x000000F7, Gq_Gq_Eq < RW, RW, R >, DummyRq< 0, RAX >, DummyRq< 2, RDX >, OSq, Group3< 5 > >,
                /**/ Opcode < I_IMUL, 0x00000FAF, Gw_Ew    < RW,     R >,                                       OSw              >,
                /**/ Opcode < I_IMUL, 0x00000FAF, Gd_Ed    < RW,     R >,                                       OSd              >,
                /**/ Opcode < I_IMUL, 0x00000FAF, Gq_Eq    < RW,     R >,                                       OSq              >,
                /**/ Opcode < I_IMUL, 0x0000006B, Gw_Ew_Ib < RW,     R >,                                       OSw              >,
                /**/ Opcode < I_IMUL, 0x0000006B, Gd_Ed_Ib < RW,     R >,                                       OSd              >,
                /**/ Opcode < I_IMUL, 0x0000006B, Gq_Eq_Ib < RW,     R >,                                       OSq              >,
                /**/ Opcode < I_IMUL, 0x00000069, Gw_Ew_Iw < RW,     R >,                                       OSw              >,
                /**/ Opcode < I_IMUL, 0x00000069, Gd_Ed_Id < RW,     R >,                                       OSd              >,
                /**/ Opcode < I_IMUL, 0x00000069, Gq_Eq_Id < RW,     R >,                                       OSq              >
                > {};

            template<> struct Opcode$< I_IN > :
                Switch
                <
                /**/ Opcode < I_IN, 0x000000E4, Gb_Ib < W    >, DummyRb< 0, AL  >,                    OSb >,
                /**/ Opcode < I_IN, 0x000000E5, Gw_Ib < W    >, DummyRw< 0, AX  >,                    OSw >,
                /**/ Opcode < I_IN, 0x000000E5, Gd_Ib < W    >, DummyRd< 0, EAX >,                    OSd >,
                /**/ Opcode < I_IN, 0x000000EC, Gb_Gw < W, R >, DummyRb< 0, AL  >, DummyRw< 1, DX  >, OSb >,
                /**/ Opcode < I_IN, 0x000000ED, Gw_Gw < W, R >, DummyRw< 0, AX  >, DummyRw< 1, DX  >, OSw >,
                /**/ Opcode < I_IN, 0x000000ED, Gd_Gw < W, R >, DummyRd< 0, EAX >, DummyRw< 1, DX  >, OSd >
                > {};

            template<> struct Opcode$< I_INC > :
                Switch
                <
                /**/ Opcode < I_INC, 0x00000040, Zw < RW >, OSw, i64 >,
                /**/ Opcode < I_INC, 0x00000040, Zd < RW >, OSd, i64 >,
                /**/ Opcode < I_INC, 0x000000FE, Eb < RW >, OSb, Group4< 0 > >,
                /**/ Opcode < I_INC, 0x000000FF, Ew < RW >, OSw, Group5< 0 > >,
                /**/ Opcode < I_INC, 0x000000FF, Ed < RW >, OSd, Group5< 0 > >,
                /**/ Opcode < I_INC, 0x000000FF, Eq < RW >, OSq, Group5< 0 > >
                > {};

            template<> struct Opcode$< I_INT > : Opcode < I_INT, 0x000000CD, Ib > {};
            
            template<> struct Opcode$< I_INT3 > : Opcode < I_INT3, 0x000000CC, None > {};

            template<> struct Opcode$< I_INTO > : Opcode < I_INTO, 0x000000CE, None > {};

            template<> struct Opcode$< I_OR  > :
                Switch
                <
                /**/ Opcode < I_OR, 0x0000000A, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_OR, 0x0000000B, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_OR, 0x0000000B, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_OR, 0x0000000B, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_OR, 0x00000008, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_OR, 0x00000009, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_OR, 0x00000009, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_OR, 0x00000009, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_OR, 0x0000000C, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_OR, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <1> >,
                /**/ Opcode < I_OR, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <1> >,
                /**/ Opcode < I_OR, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <1> >,
                /**/ Opcode < I_OR, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <1> >,
                /**/ Opcode < I_OR, 0x0000000D, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_OR, 0x0000000D, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_OR, 0x0000000D, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_OR, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <1> >,
                /**/ Opcode < I_OR, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <1> >,
                /**/ Opcode < I_OR, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <1> >
                > {};

            template<> struct Opcode$< I_OUT > :
                Switch
                <
                /**/ Opcode < I_OUT, 0x000000E6, Ib_Gb < R    >, DummyRb< 0, AL  >,                    OSb >,
                /**/ Opcode < I_OUT, 0x000000E7, Ib_Gw < R    >, DummyRw< 0, AX  >,                    OSw >,
                /**/ Opcode < I_OUT, 0x000000E7, Ib_Gd < R    >, DummyRd< 0, EAX >,                    OSd >,
                /**/ Opcode < I_OUT, 0x000000EE, Gw_Gb < R, R >, DummyRb< 0, AL  >, DummyRw< 1, DX  >, OSb >,
                /**/ Opcode < I_OUT, 0x000000EF, Gw_Gw < R, R >, DummyRw< 0, AX  >, DummyRw< 1, DX  >, OSw >,
                /**/ Opcode < I_OUT, 0x000000EF, Gw_Gd < R, R >, DummyRd< 0, EAX >, DummyRw< 1, DX  >, OSd >
                > {};

            template<> struct Opcode$< I_SBB > :
                Switch
                <
                /**/ Opcode < I_SBB, 0x0000001A, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_SBB, 0x0000001B, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_SBB, 0x0000001B, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_SBB, 0x0000001B, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_SBB, 0x00000018, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_SBB, 0x00000019, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_SBB, 0x00000019, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_SBB, 0x00000019, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_SBB, 0x0000001C, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_SBB, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x0000001D, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_SBB, 0x0000001D, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_SBB, 0x0000001D, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_SBB, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <3> >,
                /**/ Opcode < I_SBB, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <3> >
                > {};

            template<> struct Opcode$< I_SUB > :
                Switch
                <
                /**/ Opcode < I_SUB, 0x0000002A, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_SUB, 0x0000002B, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_SUB, 0x0000002B, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_SUB, 0x0000002B, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_SUB, 0x00000028, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_SUB, 0x00000029, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_SUB, 0x00000029, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_SUB, 0x00000029, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_SUB, 0x0000002C, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_SUB, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x0000002D, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_SUB, 0x0000002D, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_SUB, 0x0000002D, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_SUB, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <5> >,
                /**/ Opcode < I_SUB, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <5> >
                > {};

            template<> struct Opcode$< I_XOR > :
                Switch
                <
                /**/ Opcode < I_XOR, 0x00000032, Gb_Eb  < RW, R >, OSb             >,
                /**/ Opcode < I_XOR, 0x00000033, Gw_Ew  < RW, R >, OSw             >,
                /**/ Opcode < I_XOR, 0x00000033, Gd_Ed  < RW, R >, OSd             >,
                /**/ Opcode < I_XOR, 0x00000033, Gq_Eq  < RW, R >, OSq             >,
                /**/ Opcode < I_XOR, 0x00000030, Eb_Gb  < RW, R >, OSb             >,
                /**/ Opcode < I_XOR, 0x00000031, Ew_Gw  < RW, R >, OSw             >,
                /**/ Opcode < I_XOR, 0x00000031, Ed_Gd  < RW, R >, OSd             >,
                /**/ Opcode < I_XOR, 0x00000031, Eq_Gq  < RW, R >, OSq             >,
                /**/ Opcode < I_XOR, 0x00000034, AL_Ib  < RW    >                  >,
                /**/ Opcode < I_XOR, 0x00000080, Eb_Ib  < RW    >, OSb, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000083, Ew_Ib  < RW    >, OSw, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000083, Ed_Ib  < RW    >, OSd, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000083, Eq_Ib  < RW    >, OSq, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000035, AX_Iw  < RW    >, OSw             >,
                /**/ Opcode < I_XOR, 0x00000035, EAX_Id < RW    >, OSd             >,
                /**/ Opcode < I_XOR, 0x00000035, RAX_Id < RW    >, OSq             >,
                /**/ Opcode < I_XOR, 0x00000081, Ew_Iw  < RW    >, OSw, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000081, Ed_Id  < RW    >, OSd, Group1 <6> >,
                /**/ Opcode < I_XOR, 0x00000081, Eq_Id  < RW    >, OSq, Group1 <6> >
                > {};

            // Group 80188+
            template<> struct Opcode$< I_BOUND > :
                Switch
                <
                /**/ Opcode < I_BOUND, 0x00000062, Gw_Md < R, R >, OSw, i64 >,
                /**/ Opcode < I_BOUND, 0x00000062, Gd_Mq < R, R >, OSd, i64 >
                > {};

            template<> struct Opcode$< I_ENTER > :
                Switch
                <
                /**/ Opcode < I_ENTER, 0x000000C8, Gw_Iw_Ib < RW >, DummyRw< 0, BP  >, DummyRw< -1, SP , RW >, OSw >,
                /**/ Opcode < I_ENTER, 0x000000C8, Gd_Iw_Ib < RW >, DummyRd< 0, EBP >, DummyRd< -1, ESP, RW >, OSd >,
                /**/ Opcode < I_ENTER, 0x000000C8, Gd_Iw_Ib < RW >, DummyRq< 0, RBP >, DummyRq< -1, RSP, RW >, OSq >
                > {};

            template<> struct Opcode$< I_INS > :
                Switch
                <
                /**/ Opcode < I_INS, 0x0000006C, Yb_Gw < W, R >, DummyRw< 1, DX  >, OSb >,
                /**/ Opcode < I_INS, 0x0000006D, Yw_Gw < W, R >, DummyRw< 1, DX  >, OSw >,
                /**/ Opcode < I_INS, 0x0000006D, Yd_Gw < W, R >, DummyRw< 1, DX  >, OSd >
                > {};

            template<> struct Opcode$< I_LEAVE > :
                Switch
                <
                /**/ Opcode < I_LEAVE, 0x000000C9, Gw < RW >, DummyRw< 0, BP  >, DummyRw< -1, SP , W >, OSw >,
                /**/ Opcode < I_LEAVE, 0x000000C9, Gd < RW >, DummyRd< 0, EBP >, DummyRd< -1, ESP, W >, OSd >,
                /**/ Opcode < I_LEAVE, 0x000000C9, Gd < RW >, DummyRq< 0, RBP >, DummyRq< -1, RSP, W >, OSq >
                > {};

            template<> struct Opcode$< I_OUTS > :
                Switch
                <
                /**/ Opcode < I_OUTS, 0x0000006E, Gw_Xb < R, R >, DummyRw< 0, DX  >, OSb >,
                /**/ Opcode < I_OUTS, 0x0000006F, Gw_Xw < R, R >, DummyRw< 0, DX  >, OSw >,
                /**/ Opcode < I_OUTS, 0x0000006F, Gw_Xd < R, R >, DummyRw< 0, DX  >, OSd >
                > {};

            // Group 80286+
            template<> struct Opcode$< I_ARPL > : Opcode < I_ARPL, 0x00000063, Ew_Gw < W, R > > {};

            template<> struct Opcode$< I_CLTS > : Opcode < I_CLTS, 0x000000F06, None > {};

            // Group 80386+
            template<> struct Opcode$< I_BSF > :
                Switch
                <
                /**/ Opcode < I_BSF, 0x00000FBC, Gw_Ew < W, R >, OSw >,
                /**/ Opcode < I_BSF, 0x00000FBC, Gd_Ed < W, R >, OSd >,
                /**/ Opcode < I_BSF, 0x00000FBC, Gq_Eq < W, R >, OSq >
                > {};

            template<> struct Opcode$< I_BSR > :
                Switch
                <
                /**/ Opcode < I_BSR, 0x00000FBD, Gw_Ew < W, R >, OSw >,
                /**/ Opcode < I_BSR, 0x00000FBD, Gd_Ed < W, R >, OSd >,
                /**/ Opcode < I_BSR, 0x00000FBD, Gq_Eq < W, R >, OSq >
                > {};

            template<> struct Opcode$< I_BT > :
                Switch
                <
                /**/ Opcode < I_BT, 0x00000FA3, Ew_Gw < W, R >, OSw >,
                /**/ Opcode < I_BT, 0x00000FA3, Ed_Gd < W, R >, OSd >,
                /**/ Opcode < I_BT, 0x00000FA3, Eq_Gq < W, R >, OSq >,
                /**/ Opcode < I_BT, 0x00000FBA, Ew_Ib < W >, OSw, Group8 <4> >,
                /**/ Opcode < I_BT, 0x00000FBA, Ed_Ib < W >, OSd, Group8 <4> >,
                /**/ Opcode < I_BT, 0x00000FBA, Eq_Ib < W >, OSq, Group8 <4> >
                > {};

            template<> struct Opcode$< I_BTC > :
                Switch
                <
                /**/ Opcode < I_BTC, 0x00000FBB, Ew_Gw < RW, R >, OSw >,
                /**/ Opcode < I_BTC, 0x00000FBB, Ed_Gd < RW, R >, OSd >,
                /**/ Opcode < I_BTC, 0x00000FBB, Eq_Gq < RW, R >, OSq >,
                /**/ Opcode < I_BTC, 0x00000FBA, Ew_Ib < RW >, OSw, Group8 <7> >,
                /**/ Opcode < I_BTC, 0x00000FBA, Ed_Ib < RW >, OSd, Group8 <7> >,
                /**/ Opcode < I_BTC, 0x00000FBA, Eq_Ib < RW >, OSq, Group8 <7> >
                > {};

            template<> struct Opcode$< I_BTR > :
                Switch
                <
                /**/ Opcode < I_BTR, 0x00000FB3, Ew_Gw < RW, R >, OSw >,
                /**/ Opcode < I_BTR, 0x00000FB3, Ed_Gd < RW, R >, OSd >,
                /**/ Opcode < I_BTR, 0x00000FB3, Eq_Gq < RW, R >, OSq >,
                /**/ Opcode < I_BTR, 0x00000FBA, Ew_Ib < RW >, OSw, Group8 <6> >,
                /**/ Opcode < I_BTR, 0x00000FBA, Ed_Ib < RW >, OSd, Group8 <6> >,
                /**/ Opcode < I_BTR, 0x00000FBA, Eq_Ib < RW >, OSq, Group8 <6> >
                > {};

            template<> struct Opcode$< I_BTS > :
                Switch
                <
                /**/ Opcode < I_BTS, 0x00000FAB, Ew_Gw < RW, R >, OSw >,
                /**/ Opcode < I_BTS, 0x00000FAB, Ed_Gd < RW, R >, OSd >,
                /**/ Opcode < I_BTS, 0x00000FAB, Eq_Gq < RW, R >, OSq >,
                /**/ Opcode < I_BTS, 0x00000FBA, Ew_Ib < RW >, OSw, Group8 <5> >,
                /**/ Opcode < I_BTS, 0x00000FBA, Ed_Ib < RW >, OSd, Group8 <5> >,
                /**/ Opcode < I_BTS, 0x00000FBA, Eq_Ib < RW >, OSq, Group8 <5> >
                > {};

            template<> struct Opcode$< I_CDQ > : Opcode < I_CDQ, 0x000000099, Gd_Gd < RW, R >, DummyRd< 0, EDX >, DummyRd< 1, EDX > > {};

            template<> struct Opcode$< I_CQO > : Opcode < I_CQO, 0x000000099, Gq_Gq < RW, R >, DummyRd< 0, RDX >, DummyRd< 1, RDX > > {};

            template<> struct Opcode$< I_CWDE > : Opcode < I_CWDE, 0x000000098, Gd < RW >, DummyRd< 0, EAX > >{};

            template<> struct Opcode$< I_INT1 > : Opcode < I_INT1, 0x000000F1, None > {};

            // Group 80486+
            template<> struct Opcode$< I_BSWAP > :
                Switch
                <
                /**/ Opcode < I_BSWAP, 0x00000FC8, Zw < RW >, OSw >,
                /**/ Opcode < I_BSWAP, 0x00000FC8, Zd < RW >, OSd >,
                /**/ Opcode < I_BSWAP, 0x00000FC8, Zq < RW >, OSq >
                > {};

            template<> struct Opcode$< I_CDQE > : Opcode < I_CDQE, 0x000000098, Gq < RW >, OSq, DummyRq< 0, RAX > > {};

            template<> struct Opcode$< I_CLFLUSH > : Opcode < I_CLFLUSH, 0x000000FAE, Mb< RW >, Group15 <7> > {};

            template<> struct Opcode$< I_CMOVCC > :
                Switch
                <
                /**/ Opcode < I_CMOVCC, 0x00000F40, Gw_Ew < RW, R >, OSw >,
                /**/ Opcode < I_CMOVCC, 0x00000F40, Gd_Ed < RW, R >, OSd >,
                /**/ Opcode < I_CMOVCC, 0x00000F40, Gq_Eq < RW, R >, OSq >
                > {};

            template<> struct Opcode$< I_CMPXCHG > :
                Switch
                <
                /**/ Opcode < I_CMPXCHG, 0x00000FB0, Gb_Eb < RW, RW >, OSb >,
                /**/ Opcode < I_CMPXCHG, 0x00000FB1, Gw_Ew < RW, RW >, OSw >,
                /**/ Opcode < I_CMPXCHG, 0x00000FB1, Gd_Ed < RW, RW >, OSd >,
                /**/ Opcode < I_CMPXCHG, 0x00000FB1, Gq_Eq < RW, RW >, OSq >
                > {};

            template<> struct Opcode$< I_INVD > : Opcode < I_INVD, 0x00000F08, None > {};

            template<> struct Opcode$< I_INVLPG > : Opcode < I_INVLPG, 0x00000F01, Mb < RW > > {};

            // Group 80586+
            template<> struct Opcode$< I_CMPXCHG8B > : Opcode < I_CMPXCHG8B, 0x00000FC7, Gdd_Mq_Gdd < RW, RW, R >, DummyRd< 0, EAX >, DummyRd< 1, EDX >, DummyRd< 3, EBX >, DummyRd< 4, ECX >, Group9< 1 >, OSd >{};

            template<> struct Opcode$< I_CMPXCHG16B > : Opcode < I_CMPXCHG16B, 0x00000FC7, Gqq_Mo_Gqq < RW, RW, R >, DummyRq< 0, RAX >, DummyRq< 1, RDX >, DummyRq< 3, RBX >, DummyRq< 4, RCX >, Group9< 1 >, OSq >{};

#if 0
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
#endif
        }

        namespace encoder
        {
            template< typename Owner, size_t start_id, size_t end_id >
            struct EncodeArrayRange$
            {
                static __forceinline void Initialize(Owner & owner)
                {
                    owner.array[start_id] = encoder::Opcode$< InstrID(start_id) >::Encode;
                    EncodeArrayRange$< Owner, start_id + 1, end_id >::Initialize(owner);
                }
            };

            template< typename Owner, size_t start_id >
            struct EncodeArrayRange$ < Owner, start_id, start_id >
            {
                static __forceinline void Initialize(Owner & owner)
                {
                    owner.array[start_id] = encoder::Opcode$< InstrID(start_id) >::Encode;
                }
            };

            template< typename Derived, size_t start_id, size_t end_id, size_t bits, size_t n = (1 << bits), size_t i = (end_id - start_id) & (n - 1) >
            struct Encoder$CRTP : Encoder$CRTP < Derived, start_id, end_id - n + i, bits >
            {
                Encoder$CRTP()
                {
                    EncodeArrayRange$< Derived, end_id - n + i, end_id - 1 >::Initialize(*static_cast<Derived *>(this));
                }
            };

            template< typename Derived, size_t bits, size_t N, size_t i >
            struct Encoder$CRTP < Derived, 0, 0, bits, N, i >
            {
            };

            struct Encoder : Encoder$CRTP < Encoder, size_t(I_INVALID), size_t(I_LAST_INSTRUCTION), 8 >
            {
                bool(*array[size_t(I_LAST_INSTRUCTION)])(Instr & instr, bool is64);

                void operator()(InstrID id, Instr & instr, bool is64) const
                {
                    if (id < size_t(I_LAST_INSTRUCTION))
                    {
                        JITASM_ASSERT((array[size_t(id)])(instr, is64));
                    }
                    else
                    {
                        JITASM_ASSERT(0 && "unknown instruction");
                    }
                }
            };
        }

        void Backend::EncodeInstr(Instr & instr)
        {
            static encoder::Encoder const encode;

            encode(instr.id_, instr, is64_);
        }

#ifdef JITASM_TEST

        namespace encoder
        {
            template< typename Owner, size_t start_id, size_t end_id >
            struct TestArrayRange$
            {
                static __forceinline void Initialize(Owner & owner)
                {
                    owner.array[start_id] = encoder::Opcode$< InstrID(start_id) >::Test;
                    TestArrayRange$< Owner, start_id + 1, end_id >::Initialize(owner);
                }
            };

            template< typename Owner, size_t start_id >
            struct TestArrayRange$ < Owner, start_id, start_id >
            {
                static __forceinline void Initialize(Owner & owner)
                {
                    owner.array[start_id] = encoder::Opcode$< InstrID(start_id) >::Test;
                }
            };

            template< typename Derived, size_t start_id, size_t end_id, size_t bits, size_t n = (1 << bits), size_t i = (end_id - start_id) & (n - 1) >
            struct Tester$CRTP : Tester$CRTP < Derived, start_id, end_id - n + i, bits >
            {
                Tester$CRTP()
                {
                    TestArrayRange$< Derived, end_id - n + i, end_id - 1 >::Initialize(*static_cast<Derived *>(this));
                }
            };

            template< typename Derived, size_t bits, size_t N, size_t i >
            struct Tester$CRTP < Derived, 0, 0, bits, N, i >
            {
            };

            struct Tester : Tester$CRTP < Tester, size_t(I_INVALID), size_t(I_LAST_INSTRUCTION), 8 >
            {
                void(*array[size_t(I_LAST_INSTRUCTION)])(std::vector< Instr > & list, bool is64);

                void operator()(InstrID id, std::vector< Instr > & list, bool is64) const
                {
                    if (id < size_t(I_LAST_INSTRUCTION))
                    {
                        (array[size_t(id)])(list, is64);
                    }
                    else
                    {
                        // to do nothing
                    }
                }
            };
        }

        void Backend::TestInstr(InstrID id, std::vector< Instr > & list, bool is64)
        {
            static encoder::Tester const test;

            test(id, list, is64);
        }
#endif
    }
}
