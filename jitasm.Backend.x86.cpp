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

            template<> struct Opcode$< I_CMOVcc > :
                Switch
                <
                /**/ Opcode < I_CMOVcc, 0x00000F40, Gw_Ew < RW, R >, OSw >,
                /**/ Opcode < I_CMOVcc, 0x00000F40, Gd_Ed < RW, R >, OSd >,
                /**/ Opcode < I_CMOVcc, 0x00000F40, Gq_Eq < RW, R >, OSq >
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

        void Backend::EncodeInstr(Instr & instr)
        {
            switch (instr.id_)
            {
            case I_AAA:                 JITASM_ASSERT(encoder::Opcode$< I_AAA >::Encode(instr, is64_)); break;
            case I_AAD:                 JITASM_ASSERT(encoder::Opcode$< I_AAD >::Encode(instr, is64_)); break;
            case I_AAM:                 JITASM_ASSERT(encoder::Opcode$< I_AAM >::Encode(instr, is64_)); break;
            case I_AAS:                 JITASM_ASSERT(encoder::Opcode$< I_AAS >::Encode(instr, is64_)); break;
            case I_ADC:                 JITASM_ASSERT(encoder::Opcode$< I_ADC >::Encode(instr, is64_)); break;
            case I_ADCX:                JITASM_ASSERT(encoder::Opcode$< I_ADCX >::Encode(instr, is64_)); break;
            case I_ADD:                 JITASM_ASSERT(encoder::Opcode$< I_ADD >::Encode(instr, is64_)); break;
            case I_ADDPD:               JITASM_ASSERT(encoder::Opcode$< I_ADDPD >::Encode(instr, is64_)); break;
            case I_ADDPS:               JITASM_ASSERT(encoder::Opcode$< I_ADDPS >::Encode(instr, is64_)); break;
            case I_ADDSD:               JITASM_ASSERT(encoder::Opcode$< I_ADDSD >::Encode(instr, is64_)); break;
            case I_ADDSS:               JITASM_ASSERT(encoder::Opcode$< I_ADDSS >::Encode(instr, is64_)); break;
            case I_ADDSUBPD:            JITASM_ASSERT(encoder::Opcode$< I_ADDSUBPD >::Encode(instr, is64_)); break;
            case I_ADDSUBPS:            JITASM_ASSERT(encoder::Opcode$< I_ADDSUBPS >::Encode(instr, is64_)); break;
            case I_ADOX:                JITASM_ASSERT(encoder::Opcode$< I_ADOX >::Encode(instr, is64_)); break;
            case I_AESDEC:              JITASM_ASSERT(encoder::Opcode$< I_AESDEC >::Encode(instr, is64_)); break;
            case I_AESDECLAST:          JITASM_ASSERT(encoder::Opcode$< I_AESDECLAST >::Encode(instr, is64_)); break;
            case I_AESENC:              JITASM_ASSERT(encoder::Opcode$< I_AESENC >::Encode(instr, is64_)); break;
            case I_AESENCLAST:          JITASM_ASSERT(encoder::Opcode$< I_AESENCLAST >::Encode(instr, is64_)); break;
            case I_AESIMC:              JITASM_ASSERT(encoder::Opcode$< I_AESIMC >::Encode(instr, is64_)); break;
            case I_AESKEYGENASSIST:     JITASM_ASSERT(encoder::Opcode$< I_AESKEYGENASSIST >::Encode(instr, is64_)); break;
            case I_AND:                 JITASM_ASSERT(encoder::Opcode$< I_AND >::Encode(instr, is64_)); break;
            case I_ANDN:                JITASM_ASSERT(encoder::Opcode$< I_ANDN >::Encode(instr, is64_)); break;
            case I_ANDNPD:              JITASM_ASSERT(encoder::Opcode$< I_ANDNPD >::Encode(instr, is64_)); break;
            case I_ANDNPS:              JITASM_ASSERT(encoder::Opcode$< I_ANDNPS >::Encode(instr, is64_)); break;
            case I_ANDPD:               JITASM_ASSERT(encoder::Opcode$< I_ANDPD >::Encode(instr, is64_)); break;
            case I_ANDPS:               JITASM_ASSERT(encoder::Opcode$< I_ANDPS >::Encode(instr, is64_)); break;
            case I_ARPL:                JITASM_ASSERT(encoder::Opcode$< I_ARPL >::Encode(instr, is64_)); break;
            case I_BEXTR:               JITASM_ASSERT(encoder::Opcode$< I_BEXTR >::Encode(instr, is64_)); break;
            case I_BLCFILL:             JITASM_ASSERT(encoder::Opcode$< I_BLCFILL >::Encode(instr, is64_)); break;
            case I_BLCI:                JITASM_ASSERT(encoder::Opcode$< I_BLCI >::Encode(instr, is64_)); break;
            case I_BLCIC:               JITASM_ASSERT(encoder::Opcode$< I_BLCIC >::Encode(instr, is64_)); break;
            case I_BLCMSK:              JITASM_ASSERT(encoder::Opcode$< I_BLCMSK >::Encode(instr, is64_)); break;
            case I_BLCS:                JITASM_ASSERT(encoder::Opcode$< I_BLCS >::Encode(instr, is64_)); break;
            case I_BLENDPD:             JITASM_ASSERT(encoder::Opcode$< I_BLENDPD >::Encode(instr, is64_)); break;
            case I_BLENDPS:             JITASM_ASSERT(encoder::Opcode$< I_BLENDPS >::Encode(instr, is64_)); break;
            case I_BLENDVPD:            JITASM_ASSERT(encoder::Opcode$< I_BLENDVPD >::Encode(instr, is64_)); break;
            case I_BLENDVPS:            JITASM_ASSERT(encoder::Opcode$< I_BLENDVPS >::Encode(instr, is64_)); break;
            case I_BLSFILL:             JITASM_ASSERT(encoder::Opcode$< I_BLSFILL >::Encode(instr, is64_)); break;
            case I_BLSI:                JITASM_ASSERT(encoder::Opcode$< I_BLSI >::Encode(instr, is64_)); break;
            case I_BLSIC:               JITASM_ASSERT(encoder::Opcode$< I_BLSIC >::Encode(instr, is64_)); break;
            case I_BLSMSK:              JITASM_ASSERT(encoder::Opcode$< I_BLSMSK >::Encode(instr, is64_)); break;
            case I_BLSR:                JITASM_ASSERT(encoder::Opcode$< I_BLSR >::Encode(instr, is64_)); break;
            case I_BOUND:               JITASM_ASSERT(encoder::Opcode$< I_BOUND >::Encode(instr, is64_)); break;
            case I_BSF:                 JITASM_ASSERT(encoder::Opcode$< I_BSF >::Encode(instr, is64_)); break;
            case I_BSR:                 JITASM_ASSERT(encoder::Opcode$< I_BSR >::Encode(instr, is64_)); break;
            case I_BSWAP:               JITASM_ASSERT(encoder::Opcode$< I_BSWAP >::Encode(instr, is64_)); break;
            case I_BT:                  JITASM_ASSERT(encoder::Opcode$< I_BT >::Encode(instr, is64_)); break;
            case I_BTC:                 JITASM_ASSERT(encoder::Opcode$< I_BTC >::Encode(instr, is64_)); break;
            case I_BTR:                 JITASM_ASSERT(encoder::Opcode$< I_BTR >::Encode(instr, is64_)); break;
            case I_BTS:                 JITASM_ASSERT(encoder::Opcode$< I_BTS >::Encode(instr, is64_)); break;
            case I_BZHI:                JITASM_ASSERT(encoder::Opcode$< I_BZHI >::Encode(instr, is64_)); break;
            case I_CALL:                JITASM_ASSERT(encoder::Opcode$< I_CALL >::Encode(instr, is64_)); break;
            case I_CBW:                 JITASM_ASSERT(encoder::Opcode$< I_CBW >::Encode(instr, is64_)); break;
            case I_CDQ:                 JITASM_ASSERT(encoder::Opcode$< I_CDQ >::Encode(instr, is64_)); break;
            case I_CDQE:                JITASM_ASSERT(encoder::Opcode$< I_CDQE >::Encode(instr, is64_)); break;
            case I_CLAC:                JITASM_ASSERT(encoder::Opcode$< I_CLAC >::Encode(instr, is64_)); break;
            case I_CLC:                 JITASM_ASSERT(encoder::Opcode$< I_CLC >::Encode(instr, is64_)); break;
            case I_CLD:                 JITASM_ASSERT(encoder::Opcode$< I_CLD >::Encode(instr, is64_)); break;
            case I_CLFLUSH:             JITASM_ASSERT(encoder::Opcode$< I_CLFLUSH >::Encode(instr, is64_)); break;
            case I_CLGI:                JITASM_ASSERT(encoder::Opcode$< I_CLGI >::Encode(instr, is64_)); break;
            case I_CLI:                 JITASM_ASSERT(encoder::Opcode$< I_CLI >::Encode(instr, is64_)); break;
            case I_CLTS:                JITASM_ASSERT(encoder::Opcode$< I_CLTS >::Encode(instr, is64_)); break;
            case I_CMC:                 JITASM_ASSERT(encoder::Opcode$< I_CMC >::Encode(instr, is64_)); break;
            case I_CMOVcc:              JITASM_ASSERT(encoder::Opcode$< I_CMOVcc >::Encode(instr, is64_)); break;
            case I_CMP:                 JITASM_ASSERT(encoder::Opcode$< I_CMP >::Encode(instr, is64_)); break;
            case I_CMPPD:               JITASM_ASSERT(encoder::Opcode$< I_CMPPD >::Encode(instr, is64_)); break;
            case I_CMPPS:               JITASM_ASSERT(encoder::Opcode$< I_CMPPS >::Encode(instr, is64_)); break;
            case I_CMPS:                JITASM_ASSERT(encoder::Opcode$< I_CMPS >::Encode(instr, is64_)); break;
            case I_CMPSD:               JITASM_ASSERT(encoder::Opcode$< I_CMPSD >::Encode(instr, is64_)); break;
            case I_CMPSS:               JITASM_ASSERT(encoder::Opcode$< I_CMPSS >::Encode(instr, is64_)); break;
            case I_CMPXCHG:             JITASM_ASSERT(encoder::Opcode$< I_CMPXCHG >::Encode(instr, is64_)); break;
            case I_CMPXCHG16B:          JITASM_ASSERT(encoder::Opcode$< I_CMPXCHG16B >::Encode(instr, is64_)); break;
            case I_CMPXCHG8B:           JITASM_ASSERT(encoder::Opcode$< I_CMPXCHG8B >::Encode(instr, is64_)); break;
            case I_COMISD:              JITASM_ASSERT(encoder::Opcode$< I_COMISD >::Encode(instr, is64_)); break;
            case I_COMISS:              JITASM_ASSERT(encoder::Opcode$< I_COMISS >::Encode(instr, is64_)); break;
            case I_CPUID:               JITASM_ASSERT(encoder::Opcode$< I_CPUID >::Encode(instr, is64_)); break;
            case I_CQO:                 JITASM_ASSERT(encoder::Opcode$< I_CQO >::Encode(instr, is64_)); break;
            case I_CRC32:               JITASM_ASSERT(encoder::Opcode$< I_CRC32 >::Encode(instr, is64_)); break;
            case I_CVTDQ2PD:            JITASM_ASSERT(encoder::Opcode$< I_CVTDQ2PD >::Encode(instr, is64_)); break;
            case I_CVTDQ2PS:            JITASM_ASSERT(encoder::Opcode$< I_CVTDQ2PS >::Encode(instr, is64_)); break;
            case I_CVTPD2DQ:            JITASM_ASSERT(encoder::Opcode$< I_CVTPD2DQ >::Encode(instr, is64_)); break;
            case I_CVTPD2PI:            JITASM_ASSERT(encoder::Opcode$< I_CVTPD2PI >::Encode(instr, is64_)); break;
            case I_CVTPD2PS:            JITASM_ASSERT(encoder::Opcode$< I_CVTPD2PS >::Encode(instr, is64_)); break;
            case I_CVTPI2PD:            JITASM_ASSERT(encoder::Opcode$< I_CVTPI2PD >::Encode(instr, is64_)); break;
            case I_CVTPI2PS:            JITASM_ASSERT(encoder::Opcode$< I_CVTPI2PS >::Encode(instr, is64_)); break;
            case I_CVTPS2DQ:            JITASM_ASSERT(encoder::Opcode$< I_CVTPS2DQ >::Encode(instr, is64_)); break;
            case I_CVTPS2PD:            JITASM_ASSERT(encoder::Opcode$< I_CVTPS2PD >::Encode(instr, is64_)); break;
            case I_CVTPS2PI:            JITASM_ASSERT(encoder::Opcode$< I_CVTPS2PI >::Encode(instr, is64_)); break;
            case I_CVTSD2SI:            JITASM_ASSERT(encoder::Opcode$< I_CVTSD2SI >::Encode(instr, is64_)); break;
            case I_CVTSD2SS:            JITASM_ASSERT(encoder::Opcode$< I_CVTSD2SS >::Encode(instr, is64_)); break;
            case I_CVTSI2SD:            JITASM_ASSERT(encoder::Opcode$< I_CVTSI2SD >::Encode(instr, is64_)); break;
            case I_CVTSI2SS:            JITASM_ASSERT(encoder::Opcode$< I_CVTSI2SS >::Encode(instr, is64_)); break;
            case I_CVTSS2SD:            JITASM_ASSERT(encoder::Opcode$< I_CVTSS2SD >::Encode(instr, is64_)); break;
            case I_CVTSS2SI:            JITASM_ASSERT(encoder::Opcode$< I_CVTSS2SI >::Encode(instr, is64_)); break;
            case I_CVTTPD2DQ:           JITASM_ASSERT(encoder::Opcode$< I_CVTTPD2DQ >::Encode(instr, is64_)); break;
            case I_CVTTPD2PI:           JITASM_ASSERT(encoder::Opcode$< I_CVTTPD2PI >::Encode(instr, is64_)); break;
            case I_CVTTPS2DQ:           JITASM_ASSERT(encoder::Opcode$< I_CVTTPS2DQ >::Encode(instr, is64_)); break;
            case I_CVTTPS2PI:           JITASM_ASSERT(encoder::Opcode$< I_CVTTPS2PI >::Encode(instr, is64_)); break;
            case I_CVTTSD2SI:           JITASM_ASSERT(encoder::Opcode$< I_CVTTSD2SI >::Encode(instr, is64_)); break;
            case I_CVTTSS2SI:           JITASM_ASSERT(encoder::Opcode$< I_CVTTSS2SI >::Encode(instr, is64_)); break;
            case I_CWD:                 JITASM_ASSERT(encoder::Opcode$< I_CWD >::Encode(instr, is64_)); break;
            case I_CWDE:                JITASM_ASSERT(encoder::Opcode$< I_CWDE >::Encode(instr, is64_)); break;
            case I_DAA:                 JITASM_ASSERT(encoder::Opcode$< I_DAA >::Encode(instr, is64_)); break;
            case I_DAS:                 JITASM_ASSERT(encoder::Opcode$< I_DAS >::Encode(instr, is64_)); break;
            case I_DATA16:              JITASM_ASSERT(encoder::Opcode$< I_DATA16 >::Encode(instr, is64_)); break;
            case I_DEC:                 JITASM_ASSERT(encoder::Opcode$< I_DEC >::Encode(instr, is64_)); break;
            case I_DIV:                 JITASM_ASSERT(encoder::Opcode$< I_DIV >::Encode(instr, is64_)); break;
            case I_DIVPD:               JITASM_ASSERT(encoder::Opcode$< I_DIVPD >::Encode(instr, is64_)); break;
            case I_DIVPS:               JITASM_ASSERT(encoder::Opcode$< I_DIVPS >::Encode(instr, is64_)); break;
            case I_DIVSD:               JITASM_ASSERT(encoder::Opcode$< I_DIVSD >::Encode(instr, is64_)); break;
            case I_DIVSS:               JITASM_ASSERT(encoder::Opcode$< I_DIVSS >::Encode(instr, is64_)); break;
            case I_DPPD:                JITASM_ASSERT(encoder::Opcode$< I_DPPD >::Encode(instr, is64_)); break;
            case I_DPPS:                JITASM_ASSERT(encoder::Opcode$< I_DPPS >::Encode(instr, is64_)); break;
            case I_EMMS:                JITASM_ASSERT(encoder::Opcode$< I_EMMS >::Encode(instr, is64_)); break;
            case I_ENCLS:               JITASM_ASSERT(encoder::Opcode$< I_ENCLS >::Encode(instr, is64_)); break;
            case I_ENCLU:               JITASM_ASSERT(encoder::Opcode$< I_ENCLU >::Encode(instr, is64_)); break;
            case I_ENTER:               JITASM_ASSERT(encoder::Opcode$< I_ENTER >::Encode(instr, is64_)); break;
            case I_EXTRACTPS:           JITASM_ASSERT(encoder::Opcode$< I_EXTRACTPS >::Encode(instr, is64_)); break;
            case I_EXTRQ:               JITASM_ASSERT(encoder::Opcode$< I_EXTRQ >::Encode(instr, is64_)); break;
            case I_F2XM1:               JITASM_ASSERT(encoder::Opcode$< I_F2XM1 >::Encode(instr, is64_)); break;
            case I_FABS:                JITASM_ASSERT(encoder::Opcode$< I_FABS >::Encode(instr, is64_)); break;
            case I_FADD:                JITASM_ASSERT(encoder::Opcode$< I_FADD >::Encode(instr, is64_)); break;
            case I_FADDP:               JITASM_ASSERT(encoder::Opcode$< I_FADDP >::Encode(instr, is64_)); break;
            case I_FBLD:                JITASM_ASSERT(encoder::Opcode$< I_FBLD >::Encode(instr, is64_)); break;
            case I_FBSTP:               JITASM_ASSERT(encoder::Opcode$< I_FBSTP >::Encode(instr, is64_)); break;
            case I_FCHS:                JITASM_ASSERT(encoder::Opcode$< I_FCHS >::Encode(instr, is64_)); break;
            case I_FCMOVcc:             JITASM_ASSERT(encoder::Opcode$< I_FCMOVcc >::Encode(instr, is64_)); break;
            case I_FCOM:                JITASM_ASSERT(encoder::Opcode$< I_FCOM >::Encode(instr, is64_)); break;
            case I_FCOMI:               JITASM_ASSERT(encoder::Opcode$< I_FCOMI >::Encode(instr, is64_)); break;
            case I_FCOMP:               JITASM_ASSERT(encoder::Opcode$< I_FCOMP >::Encode(instr, is64_)); break;
            case I_FCOMPI:              JITASM_ASSERT(encoder::Opcode$< I_FCOMPI >::Encode(instr, is64_)); break;
            case I_FCOMPP:              JITASM_ASSERT(encoder::Opcode$< I_FCOMPP >::Encode(instr, is64_)); break;
            case I_FCOS:                JITASM_ASSERT(encoder::Opcode$< I_FCOS >::Encode(instr, is64_)); break;
            case I_FDECSTP:             JITASM_ASSERT(encoder::Opcode$< I_FDECSTP >::Encode(instr, is64_)); break;
            case I_FDIV:                JITASM_ASSERT(encoder::Opcode$< I_FDIV >::Encode(instr, is64_)); break;
            case I_FDIVP:               JITASM_ASSERT(encoder::Opcode$< I_FDIVP >::Encode(instr, is64_)); break;
            case I_FDIVR:               JITASM_ASSERT(encoder::Opcode$< I_FDIVR >::Encode(instr, is64_)); break;
            case I_FDIVRP:              JITASM_ASSERT(encoder::Opcode$< I_FDIVRP >::Encode(instr, is64_)); break;
            case I_FEMMS:               JITASM_ASSERT(encoder::Opcode$< I_FEMMS >::Encode(instr, is64_)); break;
            case I_FFREE:               JITASM_ASSERT(encoder::Opcode$< I_FFREE >::Encode(instr, is64_)); break;
            case I_FIADD:               JITASM_ASSERT(encoder::Opcode$< I_FIADD >::Encode(instr, is64_)); break;
            case I_FICOM:               JITASM_ASSERT(encoder::Opcode$< I_FICOM >::Encode(instr, is64_)); break;
            case I_FICOMP:              JITASM_ASSERT(encoder::Opcode$< I_FICOMP >::Encode(instr, is64_)); break;
            case I_FIDIV:               JITASM_ASSERT(encoder::Opcode$< I_FIDIV >::Encode(instr, is64_)); break;
            case I_FIDIVR:              JITASM_ASSERT(encoder::Opcode$< I_FIDIVR >::Encode(instr, is64_)); break;
            case I_FILD:                JITASM_ASSERT(encoder::Opcode$< I_FILD >::Encode(instr, is64_)); break;
            case I_FIMUL:               JITASM_ASSERT(encoder::Opcode$< I_FIMUL >::Encode(instr, is64_)); break;
            case I_FINCSTP:             JITASM_ASSERT(encoder::Opcode$< I_FINCSTP >::Encode(instr, is64_)); break;
            case I_FIST:                JITASM_ASSERT(encoder::Opcode$< I_FIST >::Encode(instr, is64_)); break;
            case I_FISTP:               JITASM_ASSERT(encoder::Opcode$< I_FISTP >::Encode(instr, is64_)); break;
            case I_FISTTP:              JITASM_ASSERT(encoder::Opcode$< I_FISTTP >::Encode(instr, is64_)); break;
            case I_FISUB:               JITASM_ASSERT(encoder::Opcode$< I_FISUB >::Encode(instr, is64_)); break;
            case I_FISUBR:              JITASM_ASSERT(encoder::Opcode$< I_FISUBR >::Encode(instr, is64_)); break;
            case I_FLD:                 JITASM_ASSERT(encoder::Opcode$< I_FLD >::Encode(instr, is64_)); break;
            case I_FLD1:                JITASM_ASSERT(encoder::Opcode$< I_FLD1 >::Encode(instr, is64_)); break;
            case I_FLDCW:               JITASM_ASSERT(encoder::Opcode$< I_FLDCW >::Encode(instr, is64_)); break;
            case I_FLDENV:              JITASM_ASSERT(encoder::Opcode$< I_FLDENV >::Encode(instr, is64_)); break;
            case I_FLDL2E:              JITASM_ASSERT(encoder::Opcode$< I_FLDL2E >::Encode(instr, is64_)); break;
            case I_FLDL2T:              JITASM_ASSERT(encoder::Opcode$< I_FLDL2T >::Encode(instr, is64_)); break;
            case I_FLDLG2:              JITASM_ASSERT(encoder::Opcode$< I_FLDLG2 >::Encode(instr, is64_)); break;
            case I_FLDLN2:              JITASM_ASSERT(encoder::Opcode$< I_FLDLN2 >::Encode(instr, is64_)); break;
            case I_FLDPI:               JITASM_ASSERT(encoder::Opcode$< I_FLDPI >::Encode(instr, is64_)); break;
            case I_FLDZ:                JITASM_ASSERT(encoder::Opcode$< I_FLDZ >::Encode(instr, is64_)); break;
            case I_FMUL:                JITASM_ASSERT(encoder::Opcode$< I_FMUL >::Encode(instr, is64_)); break;
            case I_FMULP:               JITASM_ASSERT(encoder::Opcode$< I_FMULP >::Encode(instr, is64_)); break;
            case I_FNCLEX:              JITASM_ASSERT(encoder::Opcode$< I_FNCLEX >::Encode(instr, is64_)); break;
            case I_FNINIT:              JITASM_ASSERT(encoder::Opcode$< I_FNINIT >::Encode(instr, is64_)); break;
            case I_FNOP:                JITASM_ASSERT(encoder::Opcode$< I_FNOP >::Encode(instr, is64_)); break;
            case I_FNSAVE:              JITASM_ASSERT(encoder::Opcode$< I_FNSAVE >::Encode(instr, is64_)); break;
            case I_FNSTCW:              JITASM_ASSERT(encoder::Opcode$< I_FNSTCW >::Encode(instr, is64_)); break;
            case I_FNSTENV:             JITASM_ASSERT(encoder::Opcode$< I_FNSTENV >::Encode(instr, is64_)); break;
            case I_FNSTSW:              JITASM_ASSERT(encoder::Opcode$< I_FNSTSW >::Encode(instr, is64_)); break;
            case I_FPATAN:              JITASM_ASSERT(encoder::Opcode$< I_FPATAN >::Encode(instr, is64_)); break;
            case I_FPREM:               JITASM_ASSERT(encoder::Opcode$< I_FPREM >::Encode(instr, is64_)); break;
            case I_FPREM1:              JITASM_ASSERT(encoder::Opcode$< I_FPREM1 >::Encode(instr, is64_)); break;
            case I_FPTAN:               JITASM_ASSERT(encoder::Opcode$< I_FPTAN >::Encode(instr, is64_)); break;
            case I_FRNDINT:             JITASM_ASSERT(encoder::Opcode$< I_FRNDINT >::Encode(instr, is64_)); break;
            case I_FRSTOR:              JITASM_ASSERT(encoder::Opcode$< I_FRSTOR >::Encode(instr, is64_)); break;
            case I_FSCALE:              JITASM_ASSERT(encoder::Opcode$< I_FSCALE >::Encode(instr, is64_)); break;
            case I_FSETPM:              JITASM_ASSERT(encoder::Opcode$< I_FSETPM >::Encode(instr, is64_)); break;
            case I_FSIN:                JITASM_ASSERT(encoder::Opcode$< I_FSIN >::Encode(instr, is64_)); break;
            case I_FSINCOS:             JITASM_ASSERT(encoder::Opcode$< I_FSINCOS >::Encode(instr, is64_)); break;
            case I_FSQRT:               JITASM_ASSERT(encoder::Opcode$< I_FSQRT >::Encode(instr, is64_)); break;
            case I_FST:                 JITASM_ASSERT(encoder::Opcode$< I_FST >::Encode(instr, is64_)); break;
            case I_FSTP:                JITASM_ASSERT(encoder::Opcode$< I_FSTP >::Encode(instr, is64_)); break;
            case I_FSTPNCE:             JITASM_ASSERT(encoder::Opcode$< I_FSTPNCE >::Encode(instr, is64_)); break;
            case I_FSUB:                JITASM_ASSERT(encoder::Opcode$< I_FSUB >::Encode(instr, is64_)); break;
            case I_FSUBP:               JITASM_ASSERT(encoder::Opcode$< I_FSUBP >::Encode(instr, is64_)); break;
            case I_FSUBR:               JITASM_ASSERT(encoder::Opcode$< I_FSUBR >::Encode(instr, is64_)); break;
            case I_FSUBRP:              JITASM_ASSERT(encoder::Opcode$< I_FSUBRP >::Encode(instr, is64_)); break;
            case I_FTST:                JITASM_ASSERT(encoder::Opcode$< I_FTST >::Encode(instr, is64_)); break;
            case I_FUCOM:               JITASM_ASSERT(encoder::Opcode$< I_FUCOM >::Encode(instr, is64_)); break;
            case I_FUCOMI:              JITASM_ASSERT(encoder::Opcode$< I_FUCOMI >::Encode(instr, is64_)); break;
            case I_FUCOMP:              JITASM_ASSERT(encoder::Opcode$< I_FUCOMP >::Encode(instr, is64_)); break;
            case I_FUCOMPI:             JITASM_ASSERT(encoder::Opcode$< I_FUCOMPI >::Encode(instr, is64_)); break;
            case I_FUCOMPP:             JITASM_ASSERT(encoder::Opcode$< I_FUCOMPP >::Encode(instr, is64_)); break;
            case I_FXAM:                JITASM_ASSERT(encoder::Opcode$< I_FXAM >::Encode(instr, is64_)); break;
            case I_FXCH:                JITASM_ASSERT(encoder::Opcode$< I_FXCH >::Encode(instr, is64_)); break;
            case I_FXRSTOR:             JITASM_ASSERT(encoder::Opcode$< I_FXRSTOR >::Encode(instr, is64_)); break;
            case I_FXRSTOR64:           JITASM_ASSERT(encoder::Opcode$< I_FXRSTOR64 >::Encode(instr, is64_)); break;
            case I_FXSAVE:              JITASM_ASSERT(encoder::Opcode$< I_FXSAVE >::Encode(instr, is64_)); break;
            case I_FXSAVE64:            JITASM_ASSERT(encoder::Opcode$< I_FXSAVE64 >::Encode(instr, is64_)); break;
            case I_FXTRACT:             JITASM_ASSERT(encoder::Opcode$< I_FXTRACT >::Encode(instr, is64_)); break;
            case I_FYL2X:               JITASM_ASSERT(encoder::Opcode$< I_FYL2X >::Encode(instr, is64_)); break;
            case I_FYL2XP1:             JITASM_ASSERT(encoder::Opcode$< I_FYL2XP1 >::Encode(instr, is64_)); break;
            case I_GETSEC:              JITASM_ASSERT(encoder::Opcode$< I_GETSEC >::Encode(instr, is64_)); break;
            case I_HADDPD:              JITASM_ASSERT(encoder::Opcode$< I_HADDPD >::Encode(instr, is64_)); break;
            case I_HADDPS:              JITASM_ASSERT(encoder::Opcode$< I_HADDPS >::Encode(instr, is64_)); break;
            case I_HLT:                 JITASM_ASSERT(encoder::Opcode$< I_HLT >::Encode(instr, is64_)); break;
            case I_HSUBPD:              JITASM_ASSERT(encoder::Opcode$< I_HSUBPD >::Encode(instr, is64_)); break;
            case I_HSUBPS:              JITASM_ASSERT(encoder::Opcode$< I_HSUBPS >::Encode(instr, is64_)); break;
            case I_IDIV:                JITASM_ASSERT(encoder::Opcode$< I_IDIV >::Encode(instr, is64_)); break;
            case I_IMUL:                JITASM_ASSERT(encoder::Opcode$< I_IMUL >::Encode(instr, is64_)); break;
            case I_IN:                  JITASM_ASSERT(encoder::Opcode$< I_IN >::Encode(instr, is64_)); break;
            case I_INC:                 JITASM_ASSERT(encoder::Opcode$< I_INC >::Encode(instr, is64_)); break;
            case I_INS:                 JITASM_ASSERT(encoder::Opcode$< I_INS >::Encode(instr, is64_)); break;
            case I_INSERTPS:            JITASM_ASSERT(encoder::Opcode$< I_INSERTPS >::Encode(instr, is64_)); break;
            case I_INSERTQ:             JITASM_ASSERT(encoder::Opcode$< I_INSERTQ >::Encode(instr, is64_)); break;
            case I_INT:                 JITASM_ASSERT(encoder::Opcode$< I_INT >::Encode(instr, is64_)); break;
            case I_INT1:                JITASM_ASSERT(encoder::Opcode$< I_INT1 >::Encode(instr, is64_)); break;
            case I_INT3:                JITASM_ASSERT(encoder::Opcode$< I_INT3 >::Encode(instr, is64_)); break;
            case I_INTO:                JITASM_ASSERT(encoder::Opcode$< I_INTO >::Encode(instr, is64_)); break;
            case I_INVD:                JITASM_ASSERT(encoder::Opcode$< I_INVD >::Encode(instr, is64_)); break;
            case I_INVEPT:              JITASM_ASSERT(encoder::Opcode$< I_INVEPT >::Encode(instr, is64_)); break;
            case I_INVLPG:              JITASM_ASSERT(encoder::Opcode$< I_INVLPG >::Encode(instr, is64_)); break;
            case I_INVLPGA:             JITASM_ASSERT(encoder::Opcode$< I_INVLPGA >::Encode(instr, is64_)); break;
            case I_INVPCID:             JITASM_ASSERT(encoder::Opcode$< I_INVPCID >::Encode(instr, is64_)); break;
            case I_INVVPID:             JITASM_ASSERT(encoder::Opcode$< I_INVVPID >::Encode(instr, is64_)); break;
            case I_IRET:                JITASM_ASSERT(encoder::Opcode$< I_IRET >::Encode(instr, is64_)); break;
            case I_IRETD:               JITASM_ASSERT(encoder::Opcode$< I_IRETD >::Encode(instr, is64_)); break;
            case I_IRETQ:               JITASM_ASSERT(encoder::Opcode$< I_IRETQ >::Encode(instr, is64_)); break;
            case I_JCC:                 JITASM_ASSERT(encoder::Opcode$< I_JCC >::Encode(instr, is64_)); break;
            case I_JMP:                 JITASM_ASSERT(encoder::Opcode$< I_JMP >::Encode(instr, is64_)); break;
            case I_KANDB:               JITASM_ASSERT(encoder::Opcode$< I_KANDB >::Encode(instr, is64_)); break;
            case I_KANDD:               JITASM_ASSERT(encoder::Opcode$< I_KANDD >::Encode(instr, is64_)); break;
            case I_KANDNB:              JITASM_ASSERT(encoder::Opcode$< I_KANDNB >::Encode(instr, is64_)); break;
            case I_KANDND:              JITASM_ASSERT(encoder::Opcode$< I_KANDND >::Encode(instr, is64_)); break;
            case I_KANDNQ:              JITASM_ASSERT(encoder::Opcode$< I_KANDNQ >::Encode(instr, is64_)); break;
            case I_KANDNW:              JITASM_ASSERT(encoder::Opcode$< I_KANDNW >::Encode(instr, is64_)); break;
            case I_KANDQ:               JITASM_ASSERT(encoder::Opcode$< I_KANDQ >::Encode(instr, is64_)); break;
            case I_KANDW:               JITASM_ASSERT(encoder::Opcode$< I_KANDW >::Encode(instr, is64_)); break;
            case I_KMOVB:               JITASM_ASSERT(encoder::Opcode$< I_KMOVB >::Encode(instr, is64_)); break;
            case I_KMOVD:               JITASM_ASSERT(encoder::Opcode$< I_KMOVD >::Encode(instr, is64_)); break;
            case I_KMOVQ:               JITASM_ASSERT(encoder::Opcode$< I_KMOVQ >::Encode(instr, is64_)); break;
            case I_KMOVW:               JITASM_ASSERT(encoder::Opcode$< I_KMOVW >::Encode(instr, is64_)); break;
            case I_KNOTB:               JITASM_ASSERT(encoder::Opcode$< I_KNOTB >::Encode(instr, is64_)); break;
            case I_KNOTD:               JITASM_ASSERT(encoder::Opcode$< I_KNOTD >::Encode(instr, is64_)); break;
            case I_KNOTQ:               JITASM_ASSERT(encoder::Opcode$< I_KNOTQ >::Encode(instr, is64_)); break;
            case I_KNOTW:               JITASM_ASSERT(encoder::Opcode$< I_KNOTW >::Encode(instr, is64_)); break;
            case I_KORB:                JITASM_ASSERT(encoder::Opcode$< I_KORB >::Encode(instr, is64_)); break;
            case I_KORD:                JITASM_ASSERT(encoder::Opcode$< I_KORD >::Encode(instr, is64_)); break;
            case I_KORQ:                JITASM_ASSERT(encoder::Opcode$< I_KORQ >::Encode(instr, is64_)); break;
            case I_KORTESTW:            JITASM_ASSERT(encoder::Opcode$< I_KORTESTW >::Encode(instr, is64_)); break;
            case I_KORW:                JITASM_ASSERT(encoder::Opcode$< I_KORW >::Encode(instr, is64_)); break;
            case I_KSHIFTLW:            JITASM_ASSERT(encoder::Opcode$< I_KSHIFTLW >::Encode(instr, is64_)); break;
            case I_KSHIFTRW:            JITASM_ASSERT(encoder::Opcode$< I_KSHIFTRW >::Encode(instr, is64_)); break;
            case I_KUNPCKBW:            JITASM_ASSERT(encoder::Opcode$< I_KUNPCKBW >::Encode(instr, is64_)); break;
            case I_KXNORB:              JITASM_ASSERT(encoder::Opcode$< I_KXNORB >::Encode(instr, is64_)); break;
            case I_KXNORD:              JITASM_ASSERT(encoder::Opcode$< I_KXNORD >::Encode(instr, is64_)); break;
            case I_KXNORQ:              JITASM_ASSERT(encoder::Opcode$< I_KXNORQ >::Encode(instr, is64_)); break;
            case I_KXNORW:              JITASM_ASSERT(encoder::Opcode$< I_KXNORW >::Encode(instr, is64_)); break;
            case I_KXORB:               JITASM_ASSERT(encoder::Opcode$< I_KXORB >::Encode(instr, is64_)); break;
            case I_KXORD:               JITASM_ASSERT(encoder::Opcode$< I_KXORD >::Encode(instr, is64_)); break;
            case I_KXORQ:               JITASM_ASSERT(encoder::Opcode$< I_KXORQ >::Encode(instr, is64_)); break;
            case I_KXORW:               JITASM_ASSERT(encoder::Opcode$< I_KXORW >::Encode(instr, is64_)); break;
            case I_LAHF:                JITASM_ASSERT(encoder::Opcode$< I_LAHF >::Encode(instr, is64_)); break;
            case I_LAR:                 JITASM_ASSERT(encoder::Opcode$< I_LAR >::Encode(instr, is64_)); break;
            case I_LCALL:               JITASM_ASSERT(encoder::Opcode$< I_LCALL >::Encode(instr, is64_)); break;
            case I_LDDQU:               JITASM_ASSERT(encoder::Opcode$< I_LDDQU >::Encode(instr, is64_)); break;
            case I_LDMXCSR:             JITASM_ASSERT(encoder::Opcode$< I_LDMXCSR >::Encode(instr, is64_)); break;
            case I_LDS:                 JITASM_ASSERT(encoder::Opcode$< I_LDS >::Encode(instr, is64_)); break;
            case I_LEA:                 JITASM_ASSERT(encoder::Opcode$< I_LEA >::Encode(instr, is64_)); break;
            case I_LEAVE:               JITASM_ASSERT(encoder::Opcode$< I_LEAVE >::Encode(instr, is64_)); break;
            case I_LES:                 JITASM_ASSERT(encoder::Opcode$< I_LES >::Encode(instr, is64_)); break;
            case I_LFENCE:              JITASM_ASSERT(encoder::Opcode$< I_LFENCE >::Encode(instr, is64_)); break;
            case I_LFS:                 JITASM_ASSERT(encoder::Opcode$< I_LFS >::Encode(instr, is64_)); break;
            case I_LGDT:                JITASM_ASSERT(encoder::Opcode$< I_LGDT >::Encode(instr, is64_)); break;
            case I_LGS:                 JITASM_ASSERT(encoder::Opcode$< I_LGS >::Encode(instr, is64_)); break;
            case I_LIDT:                JITASM_ASSERT(encoder::Opcode$< I_LIDT >::Encode(instr, is64_)); break;
            case I_LJMP:                JITASM_ASSERT(encoder::Opcode$< I_LJMP >::Encode(instr, is64_)); break;
            case I_LLDT:                JITASM_ASSERT(encoder::Opcode$< I_LLDT >::Encode(instr, is64_)); break;
            case I_LMSW:                JITASM_ASSERT(encoder::Opcode$< I_LMSW >::Encode(instr, is64_)); break;
            case I_LOCK:                JITASM_ASSERT(encoder::Opcode$< I_LOCK >::Encode(instr, is64_)); break;
            case I_LODS:                JITASM_ASSERT(encoder::Opcode$< I_LODS >::Encode(instr, is64_)); break;
            case I_LOOPCC:              JITASM_ASSERT(encoder::Opcode$< I_LOOPCC >::Encode(instr, is64_)); break;
            case I_LSL:                 JITASM_ASSERT(encoder::Opcode$< I_LSL >::Encode(instr, is64_)); break;
            case I_LSS:                 JITASM_ASSERT(encoder::Opcode$< I_LSS >::Encode(instr, is64_)); break;
            case I_LTR:                 JITASM_ASSERT(encoder::Opcode$< I_LTR >::Encode(instr, is64_)); break;
            case I_LZCNT:               JITASM_ASSERT(encoder::Opcode$< I_LZCNT >::Encode(instr, is64_)); break;
            case I_MASKMOVDQU:          JITASM_ASSERT(encoder::Opcode$< I_MASKMOVDQU >::Encode(instr, is64_)); break;
            case I_MASKMOVQ:            JITASM_ASSERT(encoder::Opcode$< I_MASKMOVQ >::Encode(instr, is64_)); break;
            case I_MAXPD:               JITASM_ASSERT(encoder::Opcode$< I_MAXPD >::Encode(instr, is64_)); break;
            case I_MAXPS:               JITASM_ASSERT(encoder::Opcode$< I_MAXPS >::Encode(instr, is64_)); break;
            case I_MAXSD:               JITASM_ASSERT(encoder::Opcode$< I_MAXSD >::Encode(instr, is64_)); break;
            case I_MAXSS:               JITASM_ASSERT(encoder::Opcode$< I_MAXSS >::Encode(instr, is64_)); break;
            case I_MFENCE:              JITASM_ASSERT(encoder::Opcode$< I_MFENCE >::Encode(instr, is64_)); break;
            case I_MINPD:               JITASM_ASSERT(encoder::Opcode$< I_MINPD >::Encode(instr, is64_)); break;
            case I_MINPS:               JITASM_ASSERT(encoder::Opcode$< I_MINPS >::Encode(instr, is64_)); break;
            case I_MINSD:               JITASM_ASSERT(encoder::Opcode$< I_MINSD >::Encode(instr, is64_)); break;
            case I_MINSS:               JITASM_ASSERT(encoder::Opcode$< I_MINSS >::Encode(instr, is64_)); break;
            case I_MONITOR:             JITASM_ASSERT(encoder::Opcode$< I_MONITOR >::Encode(instr, is64_)); break;
            case I_MONTMUL:             JITASM_ASSERT(encoder::Opcode$< I_MONTMUL >::Encode(instr, is64_)); break;
            case I_MOV:                 JITASM_ASSERT(encoder::Opcode$< I_MOV >::Encode(instr, is64_)); break;
            case I_MOVABS:              JITASM_ASSERT(encoder::Opcode$< I_MOVABS >::Encode(instr, is64_)); break;
            case I_MOVAPD:              JITASM_ASSERT(encoder::Opcode$< I_MOVAPD >::Encode(instr, is64_)); break;
            case I_MOVAPS:              JITASM_ASSERT(encoder::Opcode$< I_MOVAPS >::Encode(instr, is64_)); break;
            case I_MOVBE:               JITASM_ASSERT(encoder::Opcode$< I_MOVBE >::Encode(instr, is64_)); break;
            case I_MOVD:                JITASM_ASSERT(encoder::Opcode$< I_MOVD >::Encode(instr, is64_)); break;
            case I_MOVDDUP:             JITASM_ASSERT(encoder::Opcode$< I_MOVDDUP >::Encode(instr, is64_)); break;
            case I_MOVDQ2Q:             JITASM_ASSERT(encoder::Opcode$< I_MOVDQ2Q >::Encode(instr, is64_)); break;
            case I_MOVDQA:              JITASM_ASSERT(encoder::Opcode$< I_MOVDQA >::Encode(instr, is64_)); break;
            case I_MOVDQU:              JITASM_ASSERT(encoder::Opcode$< I_MOVDQU >::Encode(instr, is64_)); break;
            case I_MOVHLPS:             JITASM_ASSERT(encoder::Opcode$< I_MOVHLPS >::Encode(instr, is64_)); break;
            case I_MOVHPD:              JITASM_ASSERT(encoder::Opcode$< I_MOVHPD >::Encode(instr, is64_)); break;
            case I_MOVHPS:              JITASM_ASSERT(encoder::Opcode$< I_MOVHPS >::Encode(instr, is64_)); break;
            case I_MOVLHPS:             JITASM_ASSERT(encoder::Opcode$< I_MOVLHPS >::Encode(instr, is64_)); break;
            case I_MOVLPD:              JITASM_ASSERT(encoder::Opcode$< I_MOVLPD >::Encode(instr, is64_)); break;
            case I_MOVLPS:              JITASM_ASSERT(encoder::Opcode$< I_MOVLPS >::Encode(instr, is64_)); break;
            case I_MOVMSKPD:            JITASM_ASSERT(encoder::Opcode$< I_MOVMSKPD >::Encode(instr, is64_)); break;
            case I_MOVMSKPS:            JITASM_ASSERT(encoder::Opcode$< I_MOVMSKPS >::Encode(instr, is64_)); break;
            case I_MOVNTDQ:             JITASM_ASSERT(encoder::Opcode$< I_MOVNTDQ >::Encode(instr, is64_)); break;
            case I_MOVNTDQA:            JITASM_ASSERT(encoder::Opcode$< I_MOVNTDQA >::Encode(instr, is64_)); break;
            case I_MOVNTI:              JITASM_ASSERT(encoder::Opcode$< I_MOVNTI >::Encode(instr, is64_)); break;
            case I_MOVNTPD:             JITASM_ASSERT(encoder::Opcode$< I_MOVNTPD >::Encode(instr, is64_)); break;
            case I_MOVNTPS:             JITASM_ASSERT(encoder::Opcode$< I_MOVNTPS >::Encode(instr, is64_)); break;
            case I_MOVNTQ:              JITASM_ASSERT(encoder::Opcode$< I_MOVNTQ >::Encode(instr, is64_)); break;
            case I_MOVNTSD:             JITASM_ASSERT(encoder::Opcode$< I_MOVNTSD >::Encode(instr, is64_)); break;
            case I_MOVNTSS:             JITASM_ASSERT(encoder::Opcode$< I_MOVNTSS >::Encode(instr, is64_)); break;
            case I_MOVQ:                JITASM_ASSERT(encoder::Opcode$< I_MOVQ >::Encode(instr, is64_)); break;
            case I_MOVQ2DQ:             JITASM_ASSERT(encoder::Opcode$< I_MOVQ2DQ >::Encode(instr, is64_)); break;
            case I_MOVS:                JITASM_ASSERT(encoder::Opcode$< I_MOVS >::Encode(instr, is64_)); break;
            case I_MOVSD:               JITASM_ASSERT(encoder::Opcode$< I_MOVSD >::Encode(instr, is64_)); break;
            case I_MOVSHDUP:            JITASM_ASSERT(encoder::Opcode$< I_MOVSHDUP >::Encode(instr, is64_)); break;
            case I_MOVSLDUP:            JITASM_ASSERT(encoder::Opcode$< I_MOVSLDUP >::Encode(instr, is64_)); break;
            case I_MOVSS:               JITASM_ASSERT(encoder::Opcode$< I_MOVSS >::Encode(instr, is64_)); break;
            case I_MOVSX:               JITASM_ASSERT(encoder::Opcode$< I_MOVSX >::Encode(instr, is64_)); break;
            case I_MOVSXD:              JITASM_ASSERT(encoder::Opcode$< I_MOVSXD >::Encode(instr, is64_)); break;
            case I_MOVUPD:              JITASM_ASSERT(encoder::Opcode$< I_MOVUPD >::Encode(instr, is64_)); break;
            case I_MOVUPS:              JITASM_ASSERT(encoder::Opcode$< I_MOVUPS >::Encode(instr, is64_)); break;
            case I_MOVZX:               JITASM_ASSERT(encoder::Opcode$< I_MOVZX >::Encode(instr, is64_)); break;
            case I_MPSADBW:             JITASM_ASSERT(encoder::Opcode$< I_MPSADBW >::Encode(instr, is64_)); break;
            case I_MUL:                 JITASM_ASSERT(encoder::Opcode$< I_MUL >::Encode(instr, is64_)); break;
            case I_MULPD:               JITASM_ASSERT(encoder::Opcode$< I_MULPD >::Encode(instr, is64_)); break;
            case I_MULPS:               JITASM_ASSERT(encoder::Opcode$< I_MULPS >::Encode(instr, is64_)); break;
            case I_MULSD:               JITASM_ASSERT(encoder::Opcode$< I_MULSD >::Encode(instr, is64_)); break;
            case I_MULSS:               JITASM_ASSERT(encoder::Opcode$< I_MULSS >::Encode(instr, is64_)); break;
            case I_MULX:                JITASM_ASSERT(encoder::Opcode$< I_MULX >::Encode(instr, is64_)); break;
            case I_MWAIT:               JITASM_ASSERT(encoder::Opcode$< I_MWAIT >::Encode(instr, is64_)); break;
            case I_NEG:                 JITASM_ASSERT(encoder::Opcode$< I_NEG >::Encode(instr, is64_)); break;
            case I_NOP:                 JITASM_ASSERT(encoder::Opcode$< I_NOP >::Encode(instr, is64_)); break;
            case I_NOT:                 JITASM_ASSERT(encoder::Opcode$< I_NOT >::Encode(instr, is64_)); break;
            case I_OR:                  JITASM_ASSERT(encoder::Opcode$< I_OR >::Encode(instr, is64_)); break;
            case I_ORPD:                JITASM_ASSERT(encoder::Opcode$< I_ORPD >::Encode(instr, is64_)); break;
            case I_ORPS:                JITASM_ASSERT(encoder::Opcode$< I_ORPS >::Encode(instr, is64_)); break;
            case I_OUT:                 JITASM_ASSERT(encoder::Opcode$< I_OUT >::Encode(instr, is64_)); break;
            case I_OUTS:                JITASM_ASSERT(encoder::Opcode$< I_OUTS >::Encode(instr, is64_)); break;
            case I_PABSB:               JITASM_ASSERT(encoder::Opcode$< I_PABSB >::Encode(instr, is64_)); break;
            case I_PABSD:               JITASM_ASSERT(encoder::Opcode$< I_PABSD >::Encode(instr, is64_)); break;
            case I_PABSW:               JITASM_ASSERT(encoder::Opcode$< I_PABSW >::Encode(instr, is64_)); break;
            case I_PACKSSDW:            JITASM_ASSERT(encoder::Opcode$< I_PACKSSDW >::Encode(instr, is64_)); break;
            case I_PACKSSWB:            JITASM_ASSERT(encoder::Opcode$< I_PACKSSWB >::Encode(instr, is64_)); break;
            case I_PACKUSDW:            JITASM_ASSERT(encoder::Opcode$< I_PACKUSDW >::Encode(instr, is64_)); break;
            case I_PACKUSWB:            JITASM_ASSERT(encoder::Opcode$< I_PACKUSWB >::Encode(instr, is64_)); break;
            case I_PADDB:               JITASM_ASSERT(encoder::Opcode$< I_PADDB >::Encode(instr, is64_)); break;
            case I_PADDD:               JITASM_ASSERT(encoder::Opcode$< I_PADDD >::Encode(instr, is64_)); break;
            case I_PADDQ:               JITASM_ASSERT(encoder::Opcode$< I_PADDQ >::Encode(instr, is64_)); break;
            case I_PADDSB:              JITASM_ASSERT(encoder::Opcode$< I_PADDSB >::Encode(instr, is64_)); break;
            case I_PADDSW:              JITASM_ASSERT(encoder::Opcode$< I_PADDSW >::Encode(instr, is64_)); break;
            case I_PADDUSB:             JITASM_ASSERT(encoder::Opcode$< I_PADDUSB >::Encode(instr, is64_)); break;
            case I_PADDUSW:             JITASM_ASSERT(encoder::Opcode$< I_PADDUSW >::Encode(instr, is64_)); break;
            case I_PADDW:               JITASM_ASSERT(encoder::Opcode$< I_PADDW >::Encode(instr, is64_)); break;
            case I_PALIGNR:             JITASM_ASSERT(encoder::Opcode$< I_PALIGNR >::Encode(instr, is64_)); break;
            case I_PAND:                JITASM_ASSERT(encoder::Opcode$< I_PAND >::Encode(instr, is64_)); break;
            case I_PANDN:               JITASM_ASSERT(encoder::Opcode$< I_PANDN >::Encode(instr, is64_)); break;
            case I_PAUSE:               JITASM_ASSERT(encoder::Opcode$< I_PAUSE >::Encode(instr, is64_)); break;
            case I_PAVGB:               JITASM_ASSERT(encoder::Opcode$< I_PAVGB >::Encode(instr, is64_)); break;
            case I_PAVGUSB:             JITASM_ASSERT(encoder::Opcode$< I_PAVGUSB >::Encode(instr, is64_)); break;
            case I_PAVGW:               JITASM_ASSERT(encoder::Opcode$< I_PAVGW >::Encode(instr, is64_)); break;
            case I_PBLENDVB:            JITASM_ASSERT(encoder::Opcode$< I_PBLENDVB >::Encode(instr, is64_)); break;
            case I_PBLENDW:             JITASM_ASSERT(encoder::Opcode$< I_PBLENDW >::Encode(instr, is64_)); break;
            case I_PCLMULQDQ:           JITASM_ASSERT(encoder::Opcode$< I_PCLMULQDQ >::Encode(instr, is64_)); break;
            case I_PCMPEQB:             JITASM_ASSERT(encoder::Opcode$< I_PCMPEQB >::Encode(instr, is64_)); break;
            case I_PCMPEQD:             JITASM_ASSERT(encoder::Opcode$< I_PCMPEQD >::Encode(instr, is64_)); break;
            case I_PCMPEQQ:             JITASM_ASSERT(encoder::Opcode$< I_PCMPEQQ >::Encode(instr, is64_)); break;
            case I_PCMPEQW:             JITASM_ASSERT(encoder::Opcode$< I_PCMPEQW >::Encode(instr, is64_)); break;
            case I_PCMPESTRI:           JITASM_ASSERT(encoder::Opcode$< I_PCMPESTRI >::Encode(instr, is64_)); break;
            case I_PCMPESTRM:           JITASM_ASSERT(encoder::Opcode$< I_PCMPESTRM >::Encode(instr, is64_)); break;
            case I_PCMPGTB:             JITASM_ASSERT(encoder::Opcode$< I_PCMPGTB >::Encode(instr, is64_)); break;
            case I_PCMPGTD:             JITASM_ASSERT(encoder::Opcode$< I_PCMPGTD >::Encode(instr, is64_)); break;
            case I_PCMPGTQ:             JITASM_ASSERT(encoder::Opcode$< I_PCMPGTQ >::Encode(instr, is64_)); break;
            case I_PCMPGTW:             JITASM_ASSERT(encoder::Opcode$< I_PCMPGTW >::Encode(instr, is64_)); break;
            case I_PCMPISTRI:           JITASM_ASSERT(encoder::Opcode$< I_PCMPISTRI >::Encode(instr, is64_)); break;
            case I_PCMPISTRM:           JITASM_ASSERT(encoder::Opcode$< I_PCMPISTRM >::Encode(instr, is64_)); break;
            case I_PDEP:                JITASM_ASSERT(encoder::Opcode$< I_PDEP >::Encode(instr, is64_)); break;
            case I_PEXT:                JITASM_ASSERT(encoder::Opcode$< I_PEXT >::Encode(instr, is64_)); break;
            case I_PEXTRB:              JITASM_ASSERT(encoder::Opcode$< I_PEXTRB >::Encode(instr, is64_)); break;
            case I_PEXTRD:              JITASM_ASSERT(encoder::Opcode$< I_PEXTRD >::Encode(instr, is64_)); break;
            case I_PEXTRQ:              JITASM_ASSERT(encoder::Opcode$< I_PEXTRQ >::Encode(instr, is64_)); break;
            case I_PEXTRW:              JITASM_ASSERT(encoder::Opcode$< I_PEXTRW >::Encode(instr, is64_)); break;
            case I_PF2ID:               JITASM_ASSERT(encoder::Opcode$< I_PF2ID >::Encode(instr, is64_)); break;
            case I_PF2IW:               JITASM_ASSERT(encoder::Opcode$< I_PF2IW >::Encode(instr, is64_)); break;
            case I_PFACC:               JITASM_ASSERT(encoder::Opcode$< I_PFACC >::Encode(instr, is64_)); break;
            case I_PFADD:               JITASM_ASSERT(encoder::Opcode$< I_PFADD >::Encode(instr, is64_)); break;
            case I_PFCMPEQ:             JITASM_ASSERT(encoder::Opcode$< I_PFCMPEQ >::Encode(instr, is64_)); break;
            case I_PFCMPGE:             JITASM_ASSERT(encoder::Opcode$< I_PFCMPGE >::Encode(instr, is64_)); break;
            case I_PFCMPGT:             JITASM_ASSERT(encoder::Opcode$< I_PFCMPGT >::Encode(instr, is64_)); break;
            case I_PFMAX:               JITASM_ASSERT(encoder::Opcode$< I_PFMAX >::Encode(instr, is64_)); break;
            case I_PFMIN:               JITASM_ASSERT(encoder::Opcode$< I_PFMIN >::Encode(instr, is64_)); break;
            case I_PFMUL:               JITASM_ASSERT(encoder::Opcode$< I_PFMUL >::Encode(instr, is64_)); break;
            case I_PFNACC:              JITASM_ASSERT(encoder::Opcode$< I_PFNACC >::Encode(instr, is64_)); break;
            case I_PFPNACC:             JITASM_ASSERT(encoder::Opcode$< I_PFPNACC >::Encode(instr, is64_)); break;
            case I_PFRCP:               JITASM_ASSERT(encoder::Opcode$< I_PFRCP >::Encode(instr, is64_)); break;
            case I_PFRCPIT1:            JITASM_ASSERT(encoder::Opcode$< I_PFRCPIT1 >::Encode(instr, is64_)); break;
            case I_PFRCPIT2:            JITASM_ASSERT(encoder::Opcode$< I_PFRCPIT2 >::Encode(instr, is64_)); break;
            case I_PFRSQIT1:            JITASM_ASSERT(encoder::Opcode$< I_PFRSQIT1 >::Encode(instr, is64_)); break;
            case I_PFRSQRT:             JITASM_ASSERT(encoder::Opcode$< I_PFRSQRT >::Encode(instr, is64_)); break;
            case I_PFSUB:               JITASM_ASSERT(encoder::Opcode$< I_PFSUB >::Encode(instr, is64_)); break;
            case I_PFSUBR:              JITASM_ASSERT(encoder::Opcode$< I_PFSUBR >::Encode(instr, is64_)); break;
            case I_PHADDD:              JITASM_ASSERT(encoder::Opcode$< I_PHADDD >::Encode(instr, is64_)); break;
            case I_PHADDSW:             JITASM_ASSERT(encoder::Opcode$< I_PHADDSW >::Encode(instr, is64_)); break;
            case I_PHADDW:              JITASM_ASSERT(encoder::Opcode$< I_PHADDW >::Encode(instr, is64_)); break;
            case I_PHMINPOSUW:          JITASM_ASSERT(encoder::Opcode$< I_PHMINPOSUW >::Encode(instr, is64_)); break;
            case I_PHSUBD:              JITASM_ASSERT(encoder::Opcode$< I_PHSUBD >::Encode(instr, is64_)); break;
            case I_PHSUBSW:             JITASM_ASSERT(encoder::Opcode$< I_PHSUBSW >::Encode(instr, is64_)); break;
            case I_PHSUBW:              JITASM_ASSERT(encoder::Opcode$< I_PHSUBW >::Encode(instr, is64_)); break;
            case I_PI2FD:               JITASM_ASSERT(encoder::Opcode$< I_PI2FD >::Encode(instr, is64_)); break;
            case I_PI2FW:               JITASM_ASSERT(encoder::Opcode$< I_PI2FW >::Encode(instr, is64_)); break;
            case I_PINSRB:              JITASM_ASSERT(encoder::Opcode$< I_PINSRB >::Encode(instr, is64_)); break;
            case I_PINSRD:              JITASM_ASSERT(encoder::Opcode$< I_PINSRD >::Encode(instr, is64_)); break;
            case I_PINSRQ:              JITASM_ASSERT(encoder::Opcode$< I_PINSRQ >::Encode(instr, is64_)); break;
            case I_PINSRW:              JITASM_ASSERT(encoder::Opcode$< I_PINSRW >::Encode(instr, is64_)); break;
            case I_PMADDUBSW:           JITASM_ASSERT(encoder::Opcode$< I_PMADDUBSW >::Encode(instr, is64_)); break;
            case I_PMADDWD:             JITASM_ASSERT(encoder::Opcode$< I_PMADDWD >::Encode(instr, is64_)); break;
            case I_PMAXSB:              JITASM_ASSERT(encoder::Opcode$< I_PMAXSB >::Encode(instr, is64_)); break;
            case I_PMAXSD:              JITASM_ASSERT(encoder::Opcode$< I_PMAXSD >::Encode(instr, is64_)); break;
            case I_PMAXSW:              JITASM_ASSERT(encoder::Opcode$< I_PMAXSW >::Encode(instr, is64_)); break;
            case I_PMAXUB:              JITASM_ASSERT(encoder::Opcode$< I_PMAXUB >::Encode(instr, is64_)); break;
            case I_PMAXUD:              JITASM_ASSERT(encoder::Opcode$< I_PMAXUD >::Encode(instr, is64_)); break;
            case I_PMAXUW:              JITASM_ASSERT(encoder::Opcode$< I_PMAXUW >::Encode(instr, is64_)); break;
            case I_PMINSB:              JITASM_ASSERT(encoder::Opcode$< I_PMINSB >::Encode(instr, is64_)); break;
            case I_PMINSD:              JITASM_ASSERT(encoder::Opcode$< I_PMINSD >::Encode(instr, is64_)); break;
            case I_PMINSW:              JITASM_ASSERT(encoder::Opcode$< I_PMINSW >::Encode(instr, is64_)); break;
            case I_PMINUB:              JITASM_ASSERT(encoder::Opcode$< I_PMINUB >::Encode(instr, is64_)); break;
            case I_PMINUD:              JITASM_ASSERT(encoder::Opcode$< I_PMINUD >::Encode(instr, is64_)); break;
            case I_PMINUW:              JITASM_ASSERT(encoder::Opcode$< I_PMINUW >::Encode(instr, is64_)); break;
            case I_PMOVMSKB:            JITASM_ASSERT(encoder::Opcode$< I_PMOVMSKB >::Encode(instr, is64_)); break;
            case I_PMOVSXBD:            JITASM_ASSERT(encoder::Opcode$< I_PMOVSXBD >::Encode(instr, is64_)); break;
            case I_PMOVSXBQ:            JITASM_ASSERT(encoder::Opcode$< I_PMOVSXBQ >::Encode(instr, is64_)); break;
            case I_PMOVSXBW:            JITASM_ASSERT(encoder::Opcode$< I_PMOVSXBW >::Encode(instr, is64_)); break;
            case I_PMOVSXDQ:            JITASM_ASSERT(encoder::Opcode$< I_PMOVSXDQ >::Encode(instr, is64_)); break;
            case I_PMOVSXWD:            JITASM_ASSERT(encoder::Opcode$< I_PMOVSXWD >::Encode(instr, is64_)); break;
            case I_PMOVSXWQ:            JITASM_ASSERT(encoder::Opcode$< I_PMOVSXWQ >::Encode(instr, is64_)); break;
            case I_PMOVZXBD:            JITASM_ASSERT(encoder::Opcode$< I_PMOVZXBD >::Encode(instr, is64_)); break;
            case I_PMOVZXBQ:            JITASM_ASSERT(encoder::Opcode$< I_PMOVZXBQ >::Encode(instr, is64_)); break;
            case I_PMOVZXBW:            JITASM_ASSERT(encoder::Opcode$< I_PMOVZXBW >::Encode(instr, is64_)); break;
            case I_PMOVZXDQ:            JITASM_ASSERT(encoder::Opcode$< I_PMOVZXDQ >::Encode(instr, is64_)); break;
            case I_PMOVZXWD:            JITASM_ASSERT(encoder::Opcode$< I_PMOVZXWD >::Encode(instr, is64_)); break;
            case I_PMOVZXWQ:            JITASM_ASSERT(encoder::Opcode$< I_PMOVZXWQ >::Encode(instr, is64_)); break;
            case I_PMULDQ:              JITASM_ASSERT(encoder::Opcode$< I_PMULDQ >::Encode(instr, is64_)); break;
            case I_PMULHRSW:            JITASM_ASSERT(encoder::Opcode$< I_PMULHRSW >::Encode(instr, is64_)); break;
            case I_PMULHRW:             JITASM_ASSERT(encoder::Opcode$< I_PMULHRW >::Encode(instr, is64_)); break;
            case I_PMULHUW:             JITASM_ASSERT(encoder::Opcode$< I_PMULHUW >::Encode(instr, is64_)); break;
            case I_PMULHW:              JITASM_ASSERT(encoder::Opcode$< I_PMULHW >::Encode(instr, is64_)); break;
            case I_PMULLD:              JITASM_ASSERT(encoder::Opcode$< I_PMULLD >::Encode(instr, is64_)); break;
            case I_PMULLW:              JITASM_ASSERT(encoder::Opcode$< I_PMULLW >::Encode(instr, is64_)); break;
            case I_PMULUDQ:             JITASM_ASSERT(encoder::Opcode$< I_PMULUDQ >::Encode(instr, is64_)); break;
            case I_POP:                 JITASM_ASSERT(encoder::Opcode$< I_POP >::Encode(instr, is64_)); break;
            case I_POPAL:               JITASM_ASSERT(encoder::Opcode$< I_POPAL >::Encode(instr, is64_)); break;
            case I_POPAW:               JITASM_ASSERT(encoder::Opcode$< I_POPAW >::Encode(instr, is64_)); break;
            case I_POPCNT:              JITASM_ASSERT(encoder::Opcode$< I_POPCNT >::Encode(instr, is64_)); break;
            case I_POPF:                JITASM_ASSERT(encoder::Opcode$< I_POPF >::Encode(instr, is64_)); break;
            case I_POPFD:               JITASM_ASSERT(encoder::Opcode$< I_POPFD >::Encode(instr, is64_)); break;
            case I_POPFQ:               JITASM_ASSERT(encoder::Opcode$< I_POPFQ >::Encode(instr, is64_)); break;
            case I_POR:                 JITASM_ASSERT(encoder::Opcode$< I_POR >::Encode(instr, is64_)); break;
            case I_PREFETCH:            JITASM_ASSERT(encoder::Opcode$< I_PREFETCH >::Encode(instr, is64_)); break;
            case I_PREFETCHNTA:         JITASM_ASSERT(encoder::Opcode$< I_PREFETCHNTA >::Encode(instr, is64_)); break;
            case I_PREFETCHT0:          JITASM_ASSERT(encoder::Opcode$< I_PREFETCHT0 >::Encode(instr, is64_)); break;
            case I_PREFETCHT1:          JITASM_ASSERT(encoder::Opcode$< I_PREFETCHT1 >::Encode(instr, is64_)); break;
            case I_PREFETCHT2:          JITASM_ASSERT(encoder::Opcode$< I_PREFETCHT2 >::Encode(instr, is64_)); break;
            case I_PREFETCHW:           JITASM_ASSERT(encoder::Opcode$< I_PREFETCHW >::Encode(instr, is64_)); break;
            case I_PSADBW:              JITASM_ASSERT(encoder::Opcode$< I_PSADBW >::Encode(instr, is64_)); break;
            case I_PSHUFB:              JITASM_ASSERT(encoder::Opcode$< I_PSHUFB >::Encode(instr, is64_)); break;
            case I_PSHUFD:              JITASM_ASSERT(encoder::Opcode$< I_PSHUFD >::Encode(instr, is64_)); break;
            case I_PSHUFHW:             JITASM_ASSERT(encoder::Opcode$< I_PSHUFHW >::Encode(instr, is64_)); break;
            case I_PSHUFLW:             JITASM_ASSERT(encoder::Opcode$< I_PSHUFLW >::Encode(instr, is64_)); break;
            case I_PSHUFW:              JITASM_ASSERT(encoder::Opcode$< I_PSHUFW >::Encode(instr, is64_)); break;
            case I_PSIGNB:              JITASM_ASSERT(encoder::Opcode$< I_PSIGNB >::Encode(instr, is64_)); break;
            case I_PSIGND:              JITASM_ASSERT(encoder::Opcode$< I_PSIGND >::Encode(instr, is64_)); break;
            case I_PSIGNW:              JITASM_ASSERT(encoder::Opcode$< I_PSIGNW >::Encode(instr, is64_)); break;
            case I_PSLLD:               JITASM_ASSERT(encoder::Opcode$< I_PSLLD >::Encode(instr, is64_)); break;
            case I_PSLLDQ:              JITASM_ASSERT(encoder::Opcode$< I_PSLLDQ >::Encode(instr, is64_)); break;
            case I_PSLLQ:               JITASM_ASSERT(encoder::Opcode$< I_PSLLQ >::Encode(instr, is64_)); break;
            case I_PSLLW:               JITASM_ASSERT(encoder::Opcode$< I_PSLLW >::Encode(instr, is64_)); break;
            case I_PSRAD:               JITASM_ASSERT(encoder::Opcode$< I_PSRAD >::Encode(instr, is64_)); break;
            case I_PSRAW:               JITASM_ASSERT(encoder::Opcode$< I_PSRAW >::Encode(instr, is64_)); break;
            case I_PSRLD:               JITASM_ASSERT(encoder::Opcode$< I_PSRLD >::Encode(instr, is64_)); break;
            case I_PSRLDQ:              JITASM_ASSERT(encoder::Opcode$< I_PSRLDQ >::Encode(instr, is64_)); break;
            case I_PSRLQ:               JITASM_ASSERT(encoder::Opcode$< I_PSRLQ >::Encode(instr, is64_)); break;
            case I_PSRLW:               JITASM_ASSERT(encoder::Opcode$< I_PSRLW >::Encode(instr, is64_)); break;
            case I_PSUBB:               JITASM_ASSERT(encoder::Opcode$< I_PSUBB >::Encode(instr, is64_)); break;
            case I_PSUBD:               JITASM_ASSERT(encoder::Opcode$< I_PSUBD >::Encode(instr, is64_)); break;
            case I_PSUBQ:               JITASM_ASSERT(encoder::Opcode$< I_PSUBQ >::Encode(instr, is64_)); break;
            case I_PSUBSB:              JITASM_ASSERT(encoder::Opcode$< I_PSUBSB >::Encode(instr, is64_)); break;
            case I_PSUBSW:              JITASM_ASSERT(encoder::Opcode$< I_PSUBSW >::Encode(instr, is64_)); break;
            case I_PSUBUSB:             JITASM_ASSERT(encoder::Opcode$< I_PSUBUSB >::Encode(instr, is64_)); break;
            case I_PSUBUSW:             JITASM_ASSERT(encoder::Opcode$< I_PSUBUSW >::Encode(instr, is64_)); break;
            case I_PSUBW:               JITASM_ASSERT(encoder::Opcode$< I_PSUBW >::Encode(instr, is64_)); break;
            case I_PSWAPD:              JITASM_ASSERT(encoder::Opcode$< I_PSWAPD >::Encode(instr, is64_)); break;
            case I_PTEST:               JITASM_ASSERT(encoder::Opcode$< I_PTEST >::Encode(instr, is64_)); break;
            case I_PUNPCKHBW:           JITASM_ASSERT(encoder::Opcode$< I_PUNPCKHBW >::Encode(instr, is64_)); break;
            case I_PUNPCKHDQ:           JITASM_ASSERT(encoder::Opcode$< I_PUNPCKHDQ >::Encode(instr, is64_)); break;
            case I_PUNPCKHQDQ:          JITASM_ASSERT(encoder::Opcode$< I_PUNPCKHQDQ >::Encode(instr, is64_)); break;
            case I_PUNPCKHWD:           JITASM_ASSERT(encoder::Opcode$< I_PUNPCKHWD >::Encode(instr, is64_)); break;
            case I_PUNPCKLBW:           JITASM_ASSERT(encoder::Opcode$< I_PUNPCKLBW >::Encode(instr, is64_)); break;
            case I_PUNPCKLDQ:           JITASM_ASSERT(encoder::Opcode$< I_PUNPCKLDQ >::Encode(instr, is64_)); break;
            case I_PUNPCKLQDQ:          JITASM_ASSERT(encoder::Opcode$< I_PUNPCKLQDQ >::Encode(instr, is64_)); break;
            case I_PUNPCKLWD:           JITASM_ASSERT(encoder::Opcode$< I_PUNPCKLWD >::Encode(instr, is64_)); break;
            case I_PUSH:                JITASM_ASSERT(encoder::Opcode$< I_PUSH >::Encode(instr, is64_)); break;
            case I_PUSHAL:              JITASM_ASSERT(encoder::Opcode$< I_PUSHAL >::Encode(instr, is64_)); break;
            case I_PUSHAW:              JITASM_ASSERT(encoder::Opcode$< I_PUSHAW >::Encode(instr, is64_)); break;
            case I_PUSHF:               JITASM_ASSERT(encoder::Opcode$< I_PUSHF >::Encode(instr, is64_)); break;
            case I_PUSHFD:              JITASM_ASSERT(encoder::Opcode$< I_PUSHFD >::Encode(instr, is64_)); break;
            case I_PUSHFQ:              JITASM_ASSERT(encoder::Opcode$< I_PUSHFQ >::Encode(instr, is64_)); break;
            case I_PXOR:                JITASM_ASSERT(encoder::Opcode$< I_PXOR >::Encode(instr, is64_)); break;
            case I_RCL:                 JITASM_ASSERT(encoder::Opcode$< I_RCL >::Encode(instr, is64_)); break;
            case I_RCPPS:               JITASM_ASSERT(encoder::Opcode$< I_RCPPS >::Encode(instr, is64_)); break;
            case I_RCPSS:               JITASM_ASSERT(encoder::Opcode$< I_RCPSS >::Encode(instr, is64_)); break;
            case I_RCR:                 JITASM_ASSERT(encoder::Opcode$< I_RCR >::Encode(instr, is64_)); break;
            case I_RDFSBASE:            JITASM_ASSERT(encoder::Opcode$< I_RDFSBASE >::Encode(instr, is64_)); break;
            case I_RDGSBASE:            JITASM_ASSERT(encoder::Opcode$< I_RDGSBASE >::Encode(instr, is64_)); break;
            case I_RDMSR:               JITASM_ASSERT(encoder::Opcode$< I_RDMSR >::Encode(instr, is64_)); break;
            case I_RDPMC:               JITASM_ASSERT(encoder::Opcode$< I_RDPMC >::Encode(instr, is64_)); break;
            case I_RDRAND:              JITASM_ASSERT(encoder::Opcode$< I_RDRAND >::Encode(instr, is64_)); break;
            case I_RDSEED:              JITASM_ASSERT(encoder::Opcode$< I_RDSEED >::Encode(instr, is64_)); break;
            case I_RDTSC:               JITASM_ASSERT(encoder::Opcode$< I_RDTSC >::Encode(instr, is64_)); break;
            case I_RDTSCP:              JITASM_ASSERT(encoder::Opcode$< I_RDTSCP >::Encode(instr, is64_)); break;
            case I_REP:                 JITASM_ASSERT(encoder::Opcode$< I_REP >::Encode(instr, is64_)); break;
            case I_REPNE:               JITASM_ASSERT(encoder::Opcode$< I_REPNE >::Encode(instr, is64_)); break;
            case I_RET:                 JITASM_ASSERT(encoder::Opcode$< I_RET >::Encode(instr, is64_)); break;
            case I_RETF:                JITASM_ASSERT(encoder::Opcode$< I_RETF >::Encode(instr, is64_)); break;
            case I_RETFQ:               JITASM_ASSERT(encoder::Opcode$< I_RETFQ >::Encode(instr, is64_)); break;
            case I_ROL:                 JITASM_ASSERT(encoder::Opcode$< I_ROL >::Encode(instr, is64_)); break;
            case I_ROR:                 JITASM_ASSERT(encoder::Opcode$< I_ROR >::Encode(instr, is64_)); break;
            case I_RORX:                JITASM_ASSERT(encoder::Opcode$< I_RORX >::Encode(instr, is64_)); break;
            case I_ROUNDPD:             JITASM_ASSERT(encoder::Opcode$< I_ROUNDPD >::Encode(instr, is64_)); break;
            case I_ROUNDPS:             JITASM_ASSERT(encoder::Opcode$< I_ROUNDPS >::Encode(instr, is64_)); break;
            case I_ROUNDSD:             JITASM_ASSERT(encoder::Opcode$< I_ROUNDSD >::Encode(instr, is64_)); break;
            case I_ROUNDSS:             JITASM_ASSERT(encoder::Opcode$< I_ROUNDSS >::Encode(instr, is64_)); break;
            case I_RSM:                 JITASM_ASSERT(encoder::Opcode$< I_RSM >::Encode(instr, is64_)); break;
            case I_RSQRTPS:             JITASM_ASSERT(encoder::Opcode$< I_RSQRTPS >::Encode(instr, is64_)); break;
            case I_RSQRTSS:             JITASM_ASSERT(encoder::Opcode$< I_RSQRTSS >::Encode(instr, is64_)); break;
            case I_SAHF:                JITASM_ASSERT(encoder::Opcode$< I_SAHF >::Encode(instr, is64_)); break;
            case I_SAL:                 JITASM_ASSERT(encoder::Opcode$< I_SAL >::Encode(instr, is64_)); break;
            case I_SALC:                JITASM_ASSERT(encoder::Opcode$< I_SALC >::Encode(instr, is64_)); break;
            case I_SAR:                 JITASM_ASSERT(encoder::Opcode$< I_SAR >::Encode(instr, is64_)); break;
            case I_SARX:                JITASM_ASSERT(encoder::Opcode$< I_SARX >::Encode(instr, is64_)); break;
            case I_SBB:                 JITASM_ASSERT(encoder::Opcode$< I_SBB >::Encode(instr, is64_)); break;
            case I_SCAS:                JITASM_ASSERT(encoder::Opcode$< I_SCAS >::Encode(instr, is64_)); break;
            case I_SETcc:               JITASM_ASSERT(encoder::Opcode$< I_SETcc >::Encode(instr, is64_)); break;
            case I_SFENCE:              JITASM_ASSERT(encoder::Opcode$< I_SFENCE >::Encode(instr, is64_)); break;
            case I_SGDT:                JITASM_ASSERT(encoder::Opcode$< I_SGDT >::Encode(instr, is64_)); break;
            case I_SHA1MSG1:            JITASM_ASSERT(encoder::Opcode$< I_SHA1MSG1 >::Encode(instr, is64_)); break;
            case I_SHA1MSG2:            JITASM_ASSERT(encoder::Opcode$< I_SHA1MSG2 >::Encode(instr, is64_)); break;
            case I_SHA1NEXTE:           JITASM_ASSERT(encoder::Opcode$< I_SHA1NEXTE >::Encode(instr, is64_)); break;
            case I_SHA1RNDS4:           JITASM_ASSERT(encoder::Opcode$< I_SHA1RNDS4 >::Encode(instr, is64_)); break;
            case I_SHA256MSG1:          JITASM_ASSERT(encoder::Opcode$< I_SHA256MSG1 >::Encode(instr, is64_)); break;
            case I_SHA256MSG2:          JITASM_ASSERT(encoder::Opcode$< I_SHA256MSG2 >::Encode(instr, is64_)); break;
            case I_SHA256RNDS2:         JITASM_ASSERT(encoder::Opcode$< I_SHA256RNDS2 >::Encode(instr, is64_)); break;
            case I_SHL:                 JITASM_ASSERT(encoder::Opcode$< I_SHL >::Encode(instr, is64_)); break;
            case I_SHLD:                JITASM_ASSERT(encoder::Opcode$< I_SHLD >::Encode(instr, is64_)); break;
            case I_SHLX:                JITASM_ASSERT(encoder::Opcode$< I_SHLX >::Encode(instr, is64_)); break;
            case I_SHR:                 JITASM_ASSERT(encoder::Opcode$< I_SHR >::Encode(instr, is64_)); break;
            case I_SHRD:                JITASM_ASSERT(encoder::Opcode$< I_SHRD >::Encode(instr, is64_)); break;
            case I_SHRX:                JITASM_ASSERT(encoder::Opcode$< I_SHRX >::Encode(instr, is64_)); break;
            case I_SHUFPD:              JITASM_ASSERT(encoder::Opcode$< I_SHUFPD >::Encode(instr, is64_)); break;
            case I_SHUFPS:              JITASM_ASSERT(encoder::Opcode$< I_SHUFPS >::Encode(instr, is64_)); break;
            case I_SIDT:                JITASM_ASSERT(encoder::Opcode$< I_SIDT >::Encode(instr, is64_)); break;
            case I_SKINIT:              JITASM_ASSERT(encoder::Opcode$< I_SKINIT >::Encode(instr, is64_)); break;
            case I_SLDT:                JITASM_ASSERT(encoder::Opcode$< I_SLDT >::Encode(instr, is64_)); break;
            case I_SMSW:                JITASM_ASSERT(encoder::Opcode$< I_SMSW >::Encode(instr, is64_)); break;
            case I_SQRTPD:              JITASM_ASSERT(encoder::Opcode$< I_SQRTPD >::Encode(instr, is64_)); break;
            case I_SQRTPS:              JITASM_ASSERT(encoder::Opcode$< I_SQRTPS >::Encode(instr, is64_)); break;
            case I_SQRTSD:              JITASM_ASSERT(encoder::Opcode$< I_SQRTSD >::Encode(instr, is64_)); break;
            case I_SQRTSS:              JITASM_ASSERT(encoder::Opcode$< I_SQRTSS >::Encode(instr, is64_)); break;
            case I_STAC:                JITASM_ASSERT(encoder::Opcode$< I_STAC >::Encode(instr, is64_)); break;
            case I_STC:                 JITASM_ASSERT(encoder::Opcode$< I_STC >::Encode(instr, is64_)); break;
            case I_STD:                 JITASM_ASSERT(encoder::Opcode$< I_STD >::Encode(instr, is64_)); break;
            case I_STGI:                JITASM_ASSERT(encoder::Opcode$< I_STGI >::Encode(instr, is64_)); break;
            case I_STI:                 JITASM_ASSERT(encoder::Opcode$< I_STI >::Encode(instr, is64_)); break;
            case I_STMXCSR:             JITASM_ASSERT(encoder::Opcode$< I_STMXCSR >::Encode(instr, is64_)); break;
            case I_STOS:                JITASM_ASSERT(encoder::Opcode$< I_STOS >::Encode(instr, is64_)); break;
            case I_STR:                 JITASM_ASSERT(encoder::Opcode$< I_STR >::Encode(instr, is64_)); break;
            case I_SUB:                 JITASM_ASSERT(encoder::Opcode$< I_SUB >::Encode(instr, is64_)); break;
            case I_SUBPD:               JITASM_ASSERT(encoder::Opcode$< I_SUBPD >::Encode(instr, is64_)); break;
            case I_SUBPS:               JITASM_ASSERT(encoder::Opcode$< I_SUBPS >::Encode(instr, is64_)); break;
            case I_SUBSD:               JITASM_ASSERT(encoder::Opcode$< I_SUBSD >::Encode(instr, is64_)); break;
            case I_SUBSS:               JITASM_ASSERT(encoder::Opcode$< I_SUBSS >::Encode(instr, is64_)); break;
            case I_SWAPGS:              JITASM_ASSERT(encoder::Opcode$< I_SWAPGS >::Encode(instr, is64_)); break;
            case I_SYSCALL:             JITASM_ASSERT(encoder::Opcode$< I_SYSCALL >::Encode(instr, is64_)); break;
            case I_SYSENTER:            JITASM_ASSERT(encoder::Opcode$< I_SYSENTER >::Encode(instr, is64_)); break;
            case I_SYSEXIT:             JITASM_ASSERT(encoder::Opcode$< I_SYSEXIT >::Encode(instr, is64_)); break;
            case I_SYSRET:              JITASM_ASSERT(encoder::Opcode$< I_SYSRET >::Encode(instr, is64_)); break;
            case I_T1MSKC:              JITASM_ASSERT(encoder::Opcode$< I_T1MSKC >::Encode(instr, is64_)); break;
            case I_TEST:                JITASM_ASSERT(encoder::Opcode$< I_TEST >::Encode(instr, is64_)); break;
            case I_TZCNT:               JITASM_ASSERT(encoder::Opcode$< I_TZCNT >::Encode(instr, is64_)); break;
            case I_TZMSK:               JITASM_ASSERT(encoder::Opcode$< I_TZMSK >::Encode(instr, is64_)); break;
            case I_UCOMISD:             JITASM_ASSERT(encoder::Opcode$< I_UCOMISD >::Encode(instr, is64_)); break;
            case I_UCOMISS:             JITASM_ASSERT(encoder::Opcode$< I_UCOMISS >::Encode(instr, is64_)); break;
            case I_UD2:                 JITASM_ASSERT(encoder::Opcode$< I_UD2 >::Encode(instr, is64_)); break;
            case I_UD2B:                JITASM_ASSERT(encoder::Opcode$< I_UD2B >::Encode(instr, is64_)); break;
            case I_UNPCKHPD:            JITASM_ASSERT(encoder::Opcode$< I_UNPCKHPD >::Encode(instr, is64_)); break;
            case I_UNPCKHPS:            JITASM_ASSERT(encoder::Opcode$< I_UNPCKHPS >::Encode(instr, is64_)); break;
            case I_UNPCKLPD:            JITASM_ASSERT(encoder::Opcode$< I_UNPCKLPD >::Encode(instr, is64_)); break;
            case I_UNPCKLPS:            JITASM_ASSERT(encoder::Opcode$< I_UNPCKLPS >::Encode(instr, is64_)); break;
            case I_VADDPD:              JITASM_ASSERT(encoder::Opcode$< I_VADDPD >::Encode(instr, is64_)); break;
            case I_VADDPS:              JITASM_ASSERT(encoder::Opcode$< I_VADDPS >::Encode(instr, is64_)); break;
            case I_VADDSD:              JITASM_ASSERT(encoder::Opcode$< I_VADDSD >::Encode(instr, is64_)); break;
            case I_VADDSS:              JITASM_ASSERT(encoder::Opcode$< I_VADDSS >::Encode(instr, is64_)); break;
            case I_VADDSUBPD:           JITASM_ASSERT(encoder::Opcode$< I_VADDSUBPD >::Encode(instr, is64_)); break;
            case I_VADDSUBPS:           JITASM_ASSERT(encoder::Opcode$< I_VADDSUBPS >::Encode(instr, is64_)); break;
            case I_VAESDEC:             JITASM_ASSERT(encoder::Opcode$< I_VAESDEC >::Encode(instr, is64_)); break;
            case I_VAESDECLAST:         JITASM_ASSERT(encoder::Opcode$< I_VAESDECLAST >::Encode(instr, is64_)); break;
            case I_VAESENC:             JITASM_ASSERT(encoder::Opcode$< I_VAESENC >::Encode(instr, is64_)); break;
            case I_VAESENCLAST:         JITASM_ASSERT(encoder::Opcode$< I_VAESENCLAST >::Encode(instr, is64_)); break;
            case I_VAESIMC:             JITASM_ASSERT(encoder::Opcode$< I_VAESIMC >::Encode(instr, is64_)); break;
            case I_VAESKEYGENASSIST:    JITASM_ASSERT(encoder::Opcode$< I_VAESKEYGENASSIST >::Encode(instr, is64_)); break;
            case I_VALIGND:             JITASM_ASSERT(encoder::Opcode$< I_VALIGND >::Encode(instr, is64_)); break;
            case I_VALIGNQ:             JITASM_ASSERT(encoder::Opcode$< I_VALIGNQ >::Encode(instr, is64_)); break;
            case I_VANDNPD:             JITASM_ASSERT(encoder::Opcode$< I_VANDNPD >::Encode(instr, is64_)); break;
            case I_VANDNPS:             JITASM_ASSERT(encoder::Opcode$< I_VANDNPS >::Encode(instr, is64_)); break;
            case I_VANDPD:              JITASM_ASSERT(encoder::Opcode$< I_VANDPD >::Encode(instr, is64_)); break;
            case I_VANDPS:              JITASM_ASSERT(encoder::Opcode$< I_VANDPS >::Encode(instr, is64_)); break;
            case I_VBLENDMPD:           JITASM_ASSERT(encoder::Opcode$< I_VBLENDMPD >::Encode(instr, is64_)); break;
            case I_VBLENDMPS:           JITASM_ASSERT(encoder::Opcode$< I_VBLENDMPS >::Encode(instr, is64_)); break;
            case I_VBLENDPD:            JITASM_ASSERT(encoder::Opcode$< I_VBLENDPD >::Encode(instr, is64_)); break;
            case I_VBLENDPS:            JITASM_ASSERT(encoder::Opcode$< I_VBLENDPS >::Encode(instr, is64_)); break;
            case I_VBLENDVPD:           JITASM_ASSERT(encoder::Opcode$< I_VBLENDVPD >::Encode(instr, is64_)); break;
            case I_VBLENDVPS:           JITASM_ASSERT(encoder::Opcode$< I_VBLENDVPS >::Encode(instr, is64_)); break;
            case I_VBROADCASTF128:      JITASM_ASSERT(encoder::Opcode$< I_VBROADCASTF128 >::Encode(instr, is64_)); break;
            case I_VBROADCASTI128:      JITASM_ASSERT(encoder::Opcode$< I_VBROADCASTI128 >::Encode(instr, is64_)); break;
            case I_VBROADCASTI32X4:     JITASM_ASSERT(encoder::Opcode$< I_VBROADCASTI32X4 >::Encode(instr, is64_)); break;
            case I_VBROADCASTI64X4:     JITASM_ASSERT(encoder::Opcode$< I_VBROADCASTI64X4 >::Encode(instr, is64_)); break;
            case I_VBROADCASTSD:        JITASM_ASSERT(encoder::Opcode$< I_VBROADCASTSD >::Encode(instr, is64_)); break;
            case I_VBROADCASTSS:        JITASM_ASSERT(encoder::Opcode$< I_VBROADCASTSS >::Encode(instr, is64_)); break;
            case I_VCMP:                JITASM_ASSERT(encoder::Opcode$< I_VCMP >::Encode(instr, is64_)); break;
            case I_VCMPPD:              JITASM_ASSERT(encoder::Opcode$< I_VCMPPD >::Encode(instr, is64_)); break;
            case I_VCMPPS:              JITASM_ASSERT(encoder::Opcode$< I_VCMPPS >::Encode(instr, is64_)); break;
            case I_VCMPSD:              JITASM_ASSERT(encoder::Opcode$< I_VCMPSD >::Encode(instr, is64_)); break;
            case I_VCMPSS:              JITASM_ASSERT(encoder::Opcode$< I_VCMPSS >::Encode(instr, is64_)); break;
            case I_VCOMISD:             JITASM_ASSERT(encoder::Opcode$< I_VCOMISD >::Encode(instr, is64_)); break;
            case I_VCOMISS:             JITASM_ASSERT(encoder::Opcode$< I_VCOMISS >::Encode(instr, is64_)); break;
            case I_VCVTDQ2PD:           JITASM_ASSERT(encoder::Opcode$< I_VCVTDQ2PD >::Encode(instr, is64_)); break;
            case I_VCVTDQ2PS:           JITASM_ASSERT(encoder::Opcode$< I_VCVTDQ2PS >::Encode(instr, is64_)); break;
            case I_VCVTPD2DQ:           JITASM_ASSERT(encoder::Opcode$< I_VCVTPD2DQ >::Encode(instr, is64_)); break;
            case I_VCVTPD2DQX:          JITASM_ASSERT(encoder::Opcode$< I_VCVTPD2DQX >::Encode(instr, is64_)); break;
            case I_VCVTPD2PS:           JITASM_ASSERT(encoder::Opcode$< I_VCVTPD2PS >::Encode(instr, is64_)); break;
            case I_VCVTPD2PSX:          JITASM_ASSERT(encoder::Opcode$< I_VCVTPD2PSX >::Encode(instr, is64_)); break;
            case I_VCVTPD2UDQ:          JITASM_ASSERT(encoder::Opcode$< I_VCVTPD2UDQ >::Encode(instr, is64_)); break;
            case I_VCVTPH2PS:           JITASM_ASSERT(encoder::Opcode$< I_VCVTPH2PS >::Encode(instr, is64_)); break;
            case I_VCVTPS2DQ:           JITASM_ASSERT(encoder::Opcode$< I_VCVTPS2DQ >::Encode(instr, is64_)); break;
            case I_VCVTPS2PD:           JITASM_ASSERT(encoder::Opcode$< I_VCVTPS2PD >::Encode(instr, is64_)); break;
            case I_VCVTPS2PH:           JITASM_ASSERT(encoder::Opcode$< I_VCVTPS2PH >::Encode(instr, is64_)); break;
            case I_VCVTPS2UDQ:          JITASM_ASSERT(encoder::Opcode$< I_VCVTPS2UDQ >::Encode(instr, is64_)); break;
            case I_VCVTSD2SI:           JITASM_ASSERT(encoder::Opcode$< I_VCVTSD2SI >::Encode(instr, is64_)); break;
            case I_VCVTSD2SS:           JITASM_ASSERT(encoder::Opcode$< I_VCVTSD2SS >::Encode(instr, is64_)); break;
            case I_VCVTSD2USI:          JITASM_ASSERT(encoder::Opcode$< I_VCVTSD2USI >::Encode(instr, is64_)); break;
            case I_VCVTSI2SD:           JITASM_ASSERT(encoder::Opcode$< I_VCVTSI2SD >::Encode(instr, is64_)); break;
            case I_VCVTSI2SS:           JITASM_ASSERT(encoder::Opcode$< I_VCVTSI2SS >::Encode(instr, is64_)); break;
            case I_VCVTSS2SD:           JITASM_ASSERT(encoder::Opcode$< I_VCVTSS2SD >::Encode(instr, is64_)); break;
            case I_VCVTSS2SI:           JITASM_ASSERT(encoder::Opcode$< I_VCVTSS2SI >::Encode(instr, is64_)); break;
            case I_VCVTSS2USI:          JITASM_ASSERT(encoder::Opcode$< I_VCVTSS2USI >::Encode(instr, is64_)); break;
            case I_VCVTTPD2DQ:          JITASM_ASSERT(encoder::Opcode$< I_VCVTTPD2DQ >::Encode(instr, is64_)); break;
            case I_VCVTTPD2DQX:         JITASM_ASSERT(encoder::Opcode$< I_VCVTTPD2DQX >::Encode(instr, is64_)); break;
            case I_VCVTTPD2UDQ:         JITASM_ASSERT(encoder::Opcode$< I_VCVTTPD2UDQ >::Encode(instr, is64_)); break;
            case I_VCVTTPS2DQ:          JITASM_ASSERT(encoder::Opcode$< I_VCVTTPS2DQ >::Encode(instr, is64_)); break;
            case I_VCVTTPS2UDQ:         JITASM_ASSERT(encoder::Opcode$< I_VCVTTPS2UDQ >::Encode(instr, is64_)); break;
            case I_VCVTTSD2SI:          JITASM_ASSERT(encoder::Opcode$< I_VCVTTSD2SI >::Encode(instr, is64_)); break;
            case I_VCVTTSD2USI:         JITASM_ASSERT(encoder::Opcode$< I_VCVTTSD2USI >::Encode(instr, is64_)); break;
            case I_VCVTTSS2SI:          JITASM_ASSERT(encoder::Opcode$< I_VCVTTSS2SI >::Encode(instr, is64_)); break;
            case I_VCVTTSS2USI:         JITASM_ASSERT(encoder::Opcode$< I_VCVTTSS2USI >::Encode(instr, is64_)); break;
            case I_VCVTUDQ2PD:          JITASM_ASSERT(encoder::Opcode$< I_VCVTUDQ2PD >::Encode(instr, is64_)); break;
            case I_VCVTUDQ2PS:          JITASM_ASSERT(encoder::Opcode$< I_VCVTUDQ2PS >::Encode(instr, is64_)); break;
            case I_VCVTUSI2SD:          JITASM_ASSERT(encoder::Opcode$< I_VCVTUSI2SD >::Encode(instr, is64_)); break;
            case I_VCVTUSI2SS:          JITASM_ASSERT(encoder::Opcode$< I_VCVTUSI2SS >::Encode(instr, is64_)); break;
            case I_VDIVPD:              JITASM_ASSERT(encoder::Opcode$< I_VDIVPD >::Encode(instr, is64_)); break;
            case I_VDIVPS:              JITASM_ASSERT(encoder::Opcode$< I_VDIVPS >::Encode(instr, is64_)); break;
            case I_VDIVSD:              JITASM_ASSERT(encoder::Opcode$< I_VDIVSD >::Encode(instr, is64_)); break;
            case I_VDIVSS:              JITASM_ASSERT(encoder::Opcode$< I_VDIVSS >::Encode(instr, is64_)); break;
            case I_VDPPD:               JITASM_ASSERT(encoder::Opcode$< I_VDPPD >::Encode(instr, is64_)); break;
            case I_VDPPS:               JITASM_ASSERT(encoder::Opcode$< I_VDPPS >::Encode(instr, is64_)); break;
            case I_VERR:                JITASM_ASSERT(encoder::Opcode$< I_VERR >::Encode(instr, is64_)); break;
            case I_VERW:                JITASM_ASSERT(encoder::Opcode$< I_VERW >::Encode(instr, is64_)); break;
            case I_VEXTRACTF128:        JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTF128 >::Encode(instr, is64_)); break;
            case I_VEXTRACTF32X4:       JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTF32X4 >::Encode(instr, is64_)); break;
            case I_VEXTRACTF64X4:       JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTF64X4 >::Encode(instr, is64_)); break;
            case I_VEXTRACTI128:        JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTI128 >::Encode(instr, is64_)); break;
            case I_VEXTRACTI32X4:       JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTI32X4 >::Encode(instr, is64_)); break;
            case I_VEXTRACTI64X4:       JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTI64X4 >::Encode(instr, is64_)); break;
            case I_VEXTRACTPS:          JITASM_ASSERT(encoder::Opcode$< I_VEXTRACTPS >::Encode(instr, is64_)); break;
            case I_VFMADD132PD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD132PD >::Encode(instr, is64_)); break;
            case I_VFMADD132PS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD132PS >::Encode(instr, is64_)); break;
            case I_VFMADD132SD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD132SD >::Encode(instr, is64_)); break;
            case I_VFMADD132SS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD132SS >::Encode(instr, is64_)); break;
            case I_VFMADD213PD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD213PD >::Encode(instr, is64_)); break;
            case I_VFMADD213PS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD213PS >::Encode(instr, is64_)); break;
            case I_VFMADD213SD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD213SD >::Encode(instr, is64_)); break;
            case I_VFMADD213SS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD213SS >::Encode(instr, is64_)); break;
            case I_VFMADD231PD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD231PD >::Encode(instr, is64_)); break;
            case I_VFMADD231PS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD231PS >::Encode(instr, is64_)); break;
            case I_VFMADD231SD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD231SD >::Encode(instr, is64_)); break;
            case I_VFMADD231SS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADD231SS >::Encode(instr, is64_)); break;
            case I_VFMADDPD:            JITASM_ASSERT(encoder::Opcode$< I_VFMADDPD >::Encode(instr, is64_)); break;
            case I_VFMADDPS:            JITASM_ASSERT(encoder::Opcode$< I_VFMADDPS >::Encode(instr, is64_)); break;
            case I_VFMADDSD:            JITASM_ASSERT(encoder::Opcode$< I_VFMADDSD >::Encode(instr, is64_)); break;
            case I_VFMADDSS:            JITASM_ASSERT(encoder::Opcode$< I_VFMADDSS >::Encode(instr, is64_)); break;
            case I_VFMADDSUB132PD:      JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUB132PD >::Encode(instr, is64_)); break;
            case I_VFMADDSUB132PS:      JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUB132PS >::Encode(instr, is64_)); break;
            case I_VFMADDSUB213PD:      JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUB213PD >::Encode(instr, is64_)); break;
            case I_VFMADDSUB213PS:      JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUB213PS >::Encode(instr, is64_)); break;
            case I_VFMADDSUB231PD:      JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUB231PD >::Encode(instr, is64_)); break;
            case I_VFMADDSUB231PS:      JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUB231PS >::Encode(instr, is64_)); break;
            case I_VFMADDSUBPD:         JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUBPD >::Encode(instr, is64_)); break;
            case I_VFMADDSUBPS:         JITASM_ASSERT(encoder::Opcode$< I_VFMADDSUBPS >::Encode(instr, is64_)); break;
            case I_VFMSUB132PD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB132PD >::Encode(instr, is64_)); break;
            case I_VFMSUB132PS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB132PS >::Encode(instr, is64_)); break;
            case I_VFMSUB132SD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB132SD >::Encode(instr, is64_)); break;
            case I_VFMSUB132SS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB132SS >::Encode(instr, is64_)); break;
            case I_VFMSUB213PD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB213PD >::Encode(instr, is64_)); break;
            case I_VFMSUB213PS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB213PS >::Encode(instr, is64_)); break;
            case I_VFMSUB213SD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB213SD >::Encode(instr, is64_)); break;
            case I_VFMSUB213SS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB213SS >::Encode(instr, is64_)); break;
            case I_VFMSUB231PD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB231PD >::Encode(instr, is64_)); break;
            case I_VFMSUB231PS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB231PS >::Encode(instr, is64_)); break;
            case I_VFMSUB231SD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB231SD >::Encode(instr, is64_)); break;
            case I_VFMSUB231SS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUB231SS >::Encode(instr, is64_)); break;
            case I_VFMSUBADD132PD:      JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADD132PD >::Encode(instr, is64_)); break;
            case I_VFMSUBADD132PS:      JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADD132PS >::Encode(instr, is64_)); break;
            case I_VFMSUBADD213PD:      JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADD213PD >::Encode(instr, is64_)); break;
            case I_VFMSUBADD213PS:      JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADD213PS >::Encode(instr, is64_)); break;
            case I_VFMSUBADD231PD:      JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADD231PD >::Encode(instr, is64_)); break;
            case I_VFMSUBADD231PS:      JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADD231PS >::Encode(instr, is64_)); break;
            case I_VFMSUBADDPD:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADDPD >::Encode(instr, is64_)); break;
            case I_VFMSUBADDPS:         JITASM_ASSERT(encoder::Opcode$< I_VFMSUBADDPS >::Encode(instr, is64_)); break;
            case I_VFMSUBPD:            JITASM_ASSERT(encoder::Opcode$< I_VFMSUBPD >::Encode(instr, is64_)); break;
            case I_VFMSUBPS:            JITASM_ASSERT(encoder::Opcode$< I_VFMSUBPS >::Encode(instr, is64_)); break;
            case I_VFMSUBSD:            JITASM_ASSERT(encoder::Opcode$< I_VFMSUBSD >::Encode(instr, is64_)); break;
            case I_VFMSUBSS:            JITASM_ASSERT(encoder::Opcode$< I_VFMSUBSS >::Encode(instr, is64_)); break;
            case I_VFNMADD132PD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD132PD >::Encode(instr, is64_)); break;
            case I_VFNMADD132PS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD132PS >::Encode(instr, is64_)); break;
            case I_VFNMADD132SD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD132SD >::Encode(instr, is64_)); break;
            case I_VFNMADD132SS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD132SS >::Encode(instr, is64_)); break;
            case I_VFNMADD213PD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD213PD >::Encode(instr, is64_)); break;
            case I_VFNMADD213PS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD213PS >::Encode(instr, is64_)); break;
            case I_VFNMADD213SD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD213SD >::Encode(instr, is64_)); break;
            case I_VFNMADD213SS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD213SS >::Encode(instr, is64_)); break;
            case I_VFNMADD231PD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD231PD >::Encode(instr, is64_)); break;
            case I_VFNMADD231PS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD231PS >::Encode(instr, is64_)); break;
            case I_VFNMADD231SD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD231SD >::Encode(instr, is64_)); break;
            case I_VFNMADD231SS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMADD231SS >::Encode(instr, is64_)); break;
            case I_VFNMADDPD:           JITASM_ASSERT(encoder::Opcode$< I_VFNMADDPD >::Encode(instr, is64_)); break;
            case I_VFNMADDPS:           JITASM_ASSERT(encoder::Opcode$< I_VFNMADDPS >::Encode(instr, is64_)); break;
            case I_VFNMADDSD:           JITASM_ASSERT(encoder::Opcode$< I_VFNMADDSD >::Encode(instr, is64_)); break;
            case I_VFNMADDSS:           JITASM_ASSERT(encoder::Opcode$< I_VFNMADDSS >::Encode(instr, is64_)); break;
            case I_VFNMSUB132PD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB132PD >::Encode(instr, is64_)); break;
            case I_VFNMSUB132PS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB132PS >::Encode(instr, is64_)); break;
            case I_VFNMSUB132SD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB132SD >::Encode(instr, is64_)); break;
            case I_VFNMSUB132SS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB132SS >::Encode(instr, is64_)); break;
            case I_VFNMSUB213PD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB213PD >::Encode(instr, is64_)); break;
            case I_VFNMSUB213PS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB213PS >::Encode(instr, is64_)); break;
            case I_VFNMSUB213SD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB213SD >::Encode(instr, is64_)); break;
            case I_VFNMSUB213SS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB213SS >::Encode(instr, is64_)); break;
            case I_VFNMSUB231PD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB231PD >::Encode(instr, is64_)); break;
            case I_VFNMSUB231PS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB231PS >::Encode(instr, is64_)); break;
            case I_VFNMSUB231SD:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB231SD >::Encode(instr, is64_)); break;
            case I_VFNMSUB231SS:        JITASM_ASSERT(encoder::Opcode$< I_VFNMSUB231SS >::Encode(instr, is64_)); break;
            case I_VFNMSUBPD:           JITASM_ASSERT(encoder::Opcode$< I_VFNMSUBPD >::Encode(instr, is64_)); break;
            case I_VFNMSUBPS:           JITASM_ASSERT(encoder::Opcode$< I_VFNMSUBPS >::Encode(instr, is64_)); break;
            case I_VFNMSUBSD:           JITASM_ASSERT(encoder::Opcode$< I_VFNMSUBSD >::Encode(instr, is64_)); break;
            case I_VFNMSUBSS:           JITASM_ASSERT(encoder::Opcode$< I_VFNMSUBSS >::Encode(instr, is64_)); break;
            case I_VFRCZPD:             JITASM_ASSERT(encoder::Opcode$< I_VFRCZPD >::Encode(instr, is64_)); break;
            case I_VFRCZPS:             JITASM_ASSERT(encoder::Opcode$< I_VFRCZPS >::Encode(instr, is64_)); break;
            case I_VFRCZSD:             JITASM_ASSERT(encoder::Opcode$< I_VFRCZSD >::Encode(instr, is64_)); break;
            case I_VFRCZSS:             JITASM_ASSERT(encoder::Opcode$< I_VFRCZSS >::Encode(instr, is64_)); break;
            case I_VGATHERDPD:          JITASM_ASSERT(encoder::Opcode$< I_VGATHERDPD >::Encode(instr, is64_)); break;
            case I_VGATHERDPS:          JITASM_ASSERT(encoder::Opcode$< I_VGATHERDPS >::Encode(instr, is64_)); break;
            case I_VGATHERPF0DPD:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF0DPD >::Encode(instr, is64_)); break;
            case I_VGATHERPF0DPS:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF0DPS >::Encode(instr, is64_)); break;
            case I_VGATHERPF0QPD:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF0QPD >::Encode(instr, is64_)); break;
            case I_VGATHERPF0QPS:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF0QPS >::Encode(instr, is64_)); break;
            case I_VGATHERPF1DPD:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF1DPD >::Encode(instr, is64_)); break;
            case I_VGATHERPF1DPS:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF1DPS >::Encode(instr, is64_)); break;
            case I_VGATHERPF1QPD:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF1QPD >::Encode(instr, is64_)); break;
            case I_VGATHERPF1QPS:       JITASM_ASSERT(encoder::Opcode$< I_VGATHERPF1QPS >::Encode(instr, is64_)); break;
            case I_VGATHERQPD:          JITASM_ASSERT(encoder::Opcode$< I_VGATHERQPD >::Encode(instr, is64_)); break;
            case I_VGATHERQPS:          JITASM_ASSERT(encoder::Opcode$< I_VGATHERQPS >::Encode(instr, is64_)); break;
            case I_VHADDPD:             JITASM_ASSERT(encoder::Opcode$< I_VHADDPD >::Encode(instr, is64_)); break;
            case I_VHADDPS:             JITASM_ASSERT(encoder::Opcode$< I_VHADDPS >::Encode(instr, is64_)); break;
            case I_VHSUBPD:             JITASM_ASSERT(encoder::Opcode$< I_VHSUBPD >::Encode(instr, is64_)); break;
            case I_VHSUBPS:             JITASM_ASSERT(encoder::Opcode$< I_VHSUBPS >::Encode(instr, is64_)); break;
            case I_VINSERTF128:         JITASM_ASSERT(encoder::Opcode$< I_VINSERTF128 >::Encode(instr, is64_)); break;
            case I_VINSERTF32X4:        JITASM_ASSERT(encoder::Opcode$< I_VINSERTF32X4 >::Encode(instr, is64_)); break;
            case I_VINSERTF64X4:        JITASM_ASSERT(encoder::Opcode$< I_VINSERTF64X4 >::Encode(instr, is64_)); break;
            case I_VINSERTI128:         JITASM_ASSERT(encoder::Opcode$< I_VINSERTI128 >::Encode(instr, is64_)); break;
            case I_VINSERTI32X4:        JITASM_ASSERT(encoder::Opcode$< I_VINSERTI32X4 >::Encode(instr, is64_)); break;
            case I_VINSERTI64X4:        JITASM_ASSERT(encoder::Opcode$< I_VINSERTI64X4 >::Encode(instr, is64_)); break;
            case I_VINSERTPS:           JITASM_ASSERT(encoder::Opcode$< I_VINSERTPS >::Encode(instr, is64_)); break;
            case I_VLDDQU:              JITASM_ASSERT(encoder::Opcode$< I_VLDDQU >::Encode(instr, is64_)); break;
            case I_VLDMXCSR:            JITASM_ASSERT(encoder::Opcode$< I_VLDMXCSR >::Encode(instr, is64_)); break;
            case I_VMASKMOVDQU:         JITASM_ASSERT(encoder::Opcode$< I_VMASKMOVDQU >::Encode(instr, is64_)); break;
            case I_VMASKMOVPD:          JITASM_ASSERT(encoder::Opcode$< I_VMASKMOVPD >::Encode(instr, is64_)); break;
            case I_VMASKMOVPS:          JITASM_ASSERT(encoder::Opcode$< I_VMASKMOVPS >::Encode(instr, is64_)); break;
            case I_VMAXPD:              JITASM_ASSERT(encoder::Opcode$< I_VMAXPD >::Encode(instr, is64_)); break;
            case I_VMAXPS:              JITASM_ASSERT(encoder::Opcode$< I_VMAXPS >::Encode(instr, is64_)); break;
            case I_VMAXSD:              JITASM_ASSERT(encoder::Opcode$< I_VMAXSD >::Encode(instr, is64_)); break;
            case I_VMAXSS:              JITASM_ASSERT(encoder::Opcode$< I_VMAXSS >::Encode(instr, is64_)); break;
            case I_VMCALL:              JITASM_ASSERT(encoder::Opcode$< I_VMCALL >::Encode(instr, is64_)); break;
            case I_VMCLEAR:             JITASM_ASSERT(encoder::Opcode$< I_VMCLEAR >::Encode(instr, is64_)); break;
            case I_VMFUNC:              JITASM_ASSERT(encoder::Opcode$< I_VMFUNC >::Encode(instr, is64_)); break;
            case I_VMINPD:              JITASM_ASSERT(encoder::Opcode$< I_VMINPD >::Encode(instr, is64_)); break;
            case I_VMINPS:              JITASM_ASSERT(encoder::Opcode$< I_VMINPS >::Encode(instr, is64_)); break;
            case I_VMINSD:              JITASM_ASSERT(encoder::Opcode$< I_VMINSD >::Encode(instr, is64_)); break;
            case I_VMINSS:              JITASM_ASSERT(encoder::Opcode$< I_VMINSS >::Encode(instr, is64_)); break;
            case I_VMLAUNCH:            JITASM_ASSERT(encoder::Opcode$< I_VMLAUNCH >::Encode(instr, is64_)); break;
            case I_VMLOAD:              JITASM_ASSERT(encoder::Opcode$< I_VMLOAD >::Encode(instr, is64_)); break;
            case I_VMMCALL:             JITASM_ASSERT(encoder::Opcode$< I_VMMCALL >::Encode(instr, is64_)); break;
            case I_VMOVAPD:             JITASM_ASSERT(encoder::Opcode$< I_VMOVAPD >::Encode(instr, is64_)); break;
            case I_VMOVAPS:             JITASM_ASSERT(encoder::Opcode$< I_VMOVAPS >::Encode(instr, is64_)); break;
            case I_VMOVD:               JITASM_ASSERT(encoder::Opcode$< I_VMOVD >::Encode(instr, is64_)); break;
            case I_VMOVDDUP:            JITASM_ASSERT(encoder::Opcode$< I_VMOVDDUP >::Encode(instr, is64_)); break;
            case I_VMOVDQA:             JITASM_ASSERT(encoder::Opcode$< I_VMOVDQA >::Encode(instr, is64_)); break;
            case I_VMOVDQA32:           JITASM_ASSERT(encoder::Opcode$< I_VMOVDQA32 >::Encode(instr, is64_)); break;
            case I_VMOVDQA64:           JITASM_ASSERT(encoder::Opcode$< I_VMOVDQA64 >::Encode(instr, is64_)); break;
            case I_VMOVDQU:             JITASM_ASSERT(encoder::Opcode$< I_VMOVDQU >::Encode(instr, is64_)); break;
            case I_VMOVDQU16:           JITASM_ASSERT(encoder::Opcode$< I_VMOVDQU16 >::Encode(instr, is64_)); break;
            case I_VMOVDQU32:           JITASM_ASSERT(encoder::Opcode$< I_VMOVDQU32 >::Encode(instr, is64_)); break;
            case I_VMOVDQU64:           JITASM_ASSERT(encoder::Opcode$< I_VMOVDQU64 >::Encode(instr, is64_)); break;
            case I_VMOVDQU8:            JITASM_ASSERT(encoder::Opcode$< I_VMOVDQU8 >::Encode(instr, is64_)); break;
            case I_VMOVHLPS:            JITASM_ASSERT(encoder::Opcode$< I_VMOVHLPS >::Encode(instr, is64_)); break;
            case I_VMOVHPD:             JITASM_ASSERT(encoder::Opcode$< I_VMOVHPD >::Encode(instr, is64_)); break;
            case I_VMOVHPS:             JITASM_ASSERT(encoder::Opcode$< I_VMOVHPS >::Encode(instr, is64_)); break;
            case I_VMOVLHPS:            JITASM_ASSERT(encoder::Opcode$< I_VMOVLHPS >::Encode(instr, is64_)); break;
            case I_VMOVLPD:             JITASM_ASSERT(encoder::Opcode$< I_VMOVLPD >::Encode(instr, is64_)); break;
            case I_VMOVLPS:             JITASM_ASSERT(encoder::Opcode$< I_VMOVLPS >::Encode(instr, is64_)); break;
            case I_VMOVMSKPD:           JITASM_ASSERT(encoder::Opcode$< I_VMOVMSKPD >::Encode(instr, is64_)); break;
            case I_VMOVMSKPS:           JITASM_ASSERT(encoder::Opcode$< I_VMOVMSKPS >::Encode(instr, is64_)); break;
            case I_VMOVNTDQ:            JITASM_ASSERT(encoder::Opcode$< I_VMOVNTDQ >::Encode(instr, is64_)); break;
            case I_VMOVNTDQA:           JITASM_ASSERT(encoder::Opcode$< I_VMOVNTDQA >::Encode(instr, is64_)); break;
            case I_VMOVNTPD:            JITASM_ASSERT(encoder::Opcode$< I_VMOVNTPD >::Encode(instr, is64_)); break;
            case I_VMOVNTPS:            JITASM_ASSERT(encoder::Opcode$< I_VMOVNTPS >::Encode(instr, is64_)); break;
            case I_VMOVQ:               JITASM_ASSERT(encoder::Opcode$< I_VMOVQ >::Encode(instr, is64_)); break;
            case I_VMOVSD:              JITASM_ASSERT(encoder::Opcode$< I_VMOVSD >::Encode(instr, is64_)); break;
            case I_VMOVSHDUP:           JITASM_ASSERT(encoder::Opcode$< I_VMOVSHDUP >::Encode(instr, is64_)); break;
            case I_VMOVSLDUP:           JITASM_ASSERT(encoder::Opcode$< I_VMOVSLDUP >::Encode(instr, is64_)); break;
            case I_VMOVSS:              JITASM_ASSERT(encoder::Opcode$< I_VMOVSS >::Encode(instr, is64_)); break;
            case I_VMOVUPD:             JITASM_ASSERT(encoder::Opcode$< I_VMOVUPD >::Encode(instr, is64_)); break;
            case I_VMOVUPS:             JITASM_ASSERT(encoder::Opcode$< I_VMOVUPS >::Encode(instr, is64_)); break;
            case I_VMPSADBW:            JITASM_ASSERT(encoder::Opcode$< I_VMPSADBW >::Encode(instr, is64_)); break;
            case I_VMPTRLD:             JITASM_ASSERT(encoder::Opcode$< I_VMPTRLD >::Encode(instr, is64_)); break;
            case I_VMPTRST:             JITASM_ASSERT(encoder::Opcode$< I_VMPTRST >::Encode(instr, is64_)); break;
            case I_VMREAD:              JITASM_ASSERT(encoder::Opcode$< I_VMREAD >::Encode(instr, is64_)); break;
            case I_VMRESUME:            JITASM_ASSERT(encoder::Opcode$< I_VMRESUME >::Encode(instr, is64_)); break;
            case I_VMRUN:               JITASM_ASSERT(encoder::Opcode$< I_VMRUN >::Encode(instr, is64_)); break;
            case I_VMSAVE:              JITASM_ASSERT(encoder::Opcode$< I_VMSAVE >::Encode(instr, is64_)); break;
            case I_VMULPD:              JITASM_ASSERT(encoder::Opcode$< I_VMULPD >::Encode(instr, is64_)); break;
            case I_VMULPS:              JITASM_ASSERT(encoder::Opcode$< I_VMULPS >::Encode(instr, is64_)); break;
            case I_VMULSD:              JITASM_ASSERT(encoder::Opcode$< I_VMULSD >::Encode(instr, is64_)); break;
            case I_VMULSS:              JITASM_ASSERT(encoder::Opcode$< I_VMULSS >::Encode(instr, is64_)); break;
            case I_VMWRITE:             JITASM_ASSERT(encoder::Opcode$< I_VMWRITE >::Encode(instr, is64_)); break;
            case I_VMXOFF:              JITASM_ASSERT(encoder::Opcode$< I_VMXOFF >::Encode(instr, is64_)); break;
            case I_VMXON:               JITASM_ASSERT(encoder::Opcode$< I_VMXON >::Encode(instr, is64_)); break;
            case I_VORPD:               JITASM_ASSERT(encoder::Opcode$< I_VORPD >::Encode(instr, is64_)); break;
            case I_VORPS:               JITASM_ASSERT(encoder::Opcode$< I_VORPS >::Encode(instr, is64_)); break;
            case I_VPABSB:              JITASM_ASSERT(encoder::Opcode$< I_VPABSB >::Encode(instr, is64_)); break;
            case I_VPABSD:              JITASM_ASSERT(encoder::Opcode$< I_VPABSD >::Encode(instr, is64_)); break;
            case I_VPABSQ:              JITASM_ASSERT(encoder::Opcode$< I_VPABSQ >::Encode(instr, is64_)); break;
            case I_VPABSW:              JITASM_ASSERT(encoder::Opcode$< I_VPABSW >::Encode(instr, is64_)); break;
            case I_VPACKSSDW:           JITASM_ASSERT(encoder::Opcode$< I_VPACKSSDW >::Encode(instr, is64_)); break;
            case I_VPACKSSWB:           JITASM_ASSERT(encoder::Opcode$< I_VPACKSSWB >::Encode(instr, is64_)); break;
            case I_VPACKUSDW:           JITASM_ASSERT(encoder::Opcode$< I_VPACKUSDW >::Encode(instr, is64_)); break;
            case I_VPACKUSWB:           JITASM_ASSERT(encoder::Opcode$< I_VPACKUSWB >::Encode(instr, is64_)); break;
            case I_VPADDB:              JITASM_ASSERT(encoder::Opcode$< I_VPADDB >::Encode(instr, is64_)); break;
            case I_VPADDD:              JITASM_ASSERT(encoder::Opcode$< I_VPADDD >::Encode(instr, is64_)); break;
            case I_VPADDQ:              JITASM_ASSERT(encoder::Opcode$< I_VPADDQ >::Encode(instr, is64_)); break;
            case I_VPADDSB:             JITASM_ASSERT(encoder::Opcode$< I_VPADDSB >::Encode(instr, is64_)); break;
            case I_VPADDSW:             JITASM_ASSERT(encoder::Opcode$< I_VPADDSW >::Encode(instr, is64_)); break;
            case I_VPADDUSB:            JITASM_ASSERT(encoder::Opcode$< I_VPADDUSB >::Encode(instr, is64_)); break;
            case I_VPADDUSW:            JITASM_ASSERT(encoder::Opcode$< I_VPADDUSW >::Encode(instr, is64_)); break;
            case I_VPADDW:              JITASM_ASSERT(encoder::Opcode$< I_VPADDW >::Encode(instr, is64_)); break;
            case I_VPALIGNR:            JITASM_ASSERT(encoder::Opcode$< I_VPALIGNR >::Encode(instr, is64_)); break;
            case I_VPAND:               JITASM_ASSERT(encoder::Opcode$< I_VPAND >::Encode(instr, is64_)); break;
            case I_VPANDD:              JITASM_ASSERT(encoder::Opcode$< I_VPANDD >::Encode(instr, is64_)); break;
            case I_VPANDN:              JITASM_ASSERT(encoder::Opcode$< I_VPANDN >::Encode(instr, is64_)); break;
            case I_VPANDND:             JITASM_ASSERT(encoder::Opcode$< I_VPANDND >::Encode(instr, is64_)); break;
            case I_VPANDNQ:             JITASM_ASSERT(encoder::Opcode$< I_VPANDNQ >::Encode(instr, is64_)); break;
            case I_VPANDQ:              JITASM_ASSERT(encoder::Opcode$< I_VPANDQ >::Encode(instr, is64_)); break;
            case I_VPAVGB:              JITASM_ASSERT(encoder::Opcode$< I_VPAVGB >::Encode(instr, is64_)); break;
            case I_VPAVGW:              JITASM_ASSERT(encoder::Opcode$< I_VPAVGW >::Encode(instr, is64_)); break;
            case I_VPBLENDD:            JITASM_ASSERT(encoder::Opcode$< I_VPBLENDD >::Encode(instr, is64_)); break;
            case I_VPBLENDMD:           JITASM_ASSERT(encoder::Opcode$< I_VPBLENDMD >::Encode(instr, is64_)); break;
            case I_VPBLENDMQ:           JITASM_ASSERT(encoder::Opcode$< I_VPBLENDMQ >::Encode(instr, is64_)); break;
            case I_VPBLENDVB:           JITASM_ASSERT(encoder::Opcode$< I_VPBLENDVB >::Encode(instr, is64_)); break;
            case I_VPBLENDW:            JITASM_ASSERT(encoder::Opcode$< I_VPBLENDW >::Encode(instr, is64_)); break;
            case I_VPBROADCASTB:        JITASM_ASSERT(encoder::Opcode$< I_VPBROADCASTB >::Encode(instr, is64_)); break;
            case I_VPBROADCASTD:        JITASM_ASSERT(encoder::Opcode$< I_VPBROADCASTD >::Encode(instr, is64_)); break;
            case I_VPBROADCASTMB2Q:     JITASM_ASSERT(encoder::Opcode$< I_VPBROADCASTMB2Q >::Encode(instr, is64_)); break;
            case I_VPBROADCASTMW2D:     JITASM_ASSERT(encoder::Opcode$< I_VPBROADCASTMW2D >::Encode(instr, is64_)); break;
            case I_VPBROADCASTQ:        JITASM_ASSERT(encoder::Opcode$< I_VPBROADCASTQ >::Encode(instr, is64_)); break;
            case I_VPBROADCASTW:        JITASM_ASSERT(encoder::Opcode$< I_VPBROADCASTW >::Encode(instr, is64_)); break;
            case I_VPCLMULQDQ:          JITASM_ASSERT(encoder::Opcode$< I_VPCLMULQDQ >::Encode(instr, is64_)); break;
            case I_VPCMOV:              JITASM_ASSERT(encoder::Opcode$< I_VPCMOV >::Encode(instr, is64_)); break;
            case I_VPCMP:               JITASM_ASSERT(encoder::Opcode$< I_VPCMP >::Encode(instr, is64_)); break;
            case I_VPCMPD:              JITASM_ASSERT(encoder::Opcode$< I_VPCMPD >::Encode(instr, is64_)); break;
            case I_VPCMPEQB:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPEQB >::Encode(instr, is64_)); break;
            case I_VPCMPEQD:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPEQD >::Encode(instr, is64_)); break;
            case I_VPCMPEQQ:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPEQQ >::Encode(instr, is64_)); break;
            case I_VPCMPEQW:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPEQW >::Encode(instr, is64_)); break;
            case I_VPCMPESTRI:          JITASM_ASSERT(encoder::Opcode$< I_VPCMPESTRI >::Encode(instr, is64_)); break;
            case I_VPCMPESTRM:          JITASM_ASSERT(encoder::Opcode$< I_VPCMPESTRM >::Encode(instr, is64_)); break;
            case I_VPCMPGTB:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPGTB >::Encode(instr, is64_)); break;
            case I_VPCMPGTD:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPGTD >::Encode(instr, is64_)); break;
            case I_VPCMPGTQ:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPGTQ >::Encode(instr, is64_)); break;
            case I_VPCMPGTW:            JITASM_ASSERT(encoder::Opcode$< I_VPCMPGTW >::Encode(instr, is64_)); break;
            case I_VPCMPISTRI:          JITASM_ASSERT(encoder::Opcode$< I_VPCMPISTRI >::Encode(instr, is64_)); break;
            case I_VPCMPISTRM:          JITASM_ASSERT(encoder::Opcode$< I_VPCMPISTRM >::Encode(instr, is64_)); break;
            case I_VPCMPQ:              JITASM_ASSERT(encoder::Opcode$< I_VPCMPQ >::Encode(instr, is64_)); break;
            case I_VPCMPUD:             JITASM_ASSERT(encoder::Opcode$< I_VPCMPUD >::Encode(instr, is64_)); break;
            case I_VPCMPUQ:             JITASM_ASSERT(encoder::Opcode$< I_VPCMPUQ >::Encode(instr, is64_)); break;
            case I_VPCOMB:              JITASM_ASSERT(encoder::Opcode$< I_VPCOMB >::Encode(instr, is64_)); break;
            case I_VPCOMD:              JITASM_ASSERT(encoder::Opcode$< I_VPCOMD >::Encode(instr, is64_)); break;
            case I_VPCOMQ:              JITASM_ASSERT(encoder::Opcode$< I_VPCOMQ >::Encode(instr, is64_)); break;
            case I_VPCOMUB:             JITASM_ASSERT(encoder::Opcode$< I_VPCOMUB >::Encode(instr, is64_)); break;
            case I_VPCOMUD:             JITASM_ASSERT(encoder::Opcode$< I_VPCOMUD >::Encode(instr, is64_)); break;
            case I_VPCOMUQ:             JITASM_ASSERT(encoder::Opcode$< I_VPCOMUQ >::Encode(instr, is64_)); break;
            case I_VPCOMUW:             JITASM_ASSERT(encoder::Opcode$< I_VPCOMUW >::Encode(instr, is64_)); break;
            case I_VPCOMW:              JITASM_ASSERT(encoder::Opcode$< I_VPCOMW >::Encode(instr, is64_)); break;
            case I_VPCONFLICTD:         JITASM_ASSERT(encoder::Opcode$< I_VPCONFLICTD >::Encode(instr, is64_)); break;
            case I_VPCONFLICTQ:         JITASM_ASSERT(encoder::Opcode$< I_VPCONFLICTQ >::Encode(instr, is64_)); break;
            case I_VPERM2F128:          JITASM_ASSERT(encoder::Opcode$< I_VPERM2F128 >::Encode(instr, is64_)); break;
            case I_VPERM2I128:          JITASM_ASSERT(encoder::Opcode$< I_VPERM2I128 >::Encode(instr, is64_)); break;
            case I_VPERMD:              JITASM_ASSERT(encoder::Opcode$< I_VPERMD >::Encode(instr, is64_)); break;
            case I_VPERMI2D:            JITASM_ASSERT(encoder::Opcode$< I_VPERMI2D >::Encode(instr, is64_)); break;
            case I_VPERMI2PD:           JITASM_ASSERT(encoder::Opcode$< I_VPERMI2PD >::Encode(instr, is64_)); break;
            case I_VPERMI2PS:           JITASM_ASSERT(encoder::Opcode$< I_VPERMI2PS >::Encode(instr, is64_)); break;
            case I_VPERMI2Q:            JITASM_ASSERT(encoder::Opcode$< I_VPERMI2Q >::Encode(instr, is64_)); break;
            case I_VPERMIL2PD:          JITASM_ASSERT(encoder::Opcode$< I_VPERMIL2PD >::Encode(instr, is64_)); break;
            case I_VPERMIL2PS:          JITASM_ASSERT(encoder::Opcode$< I_VPERMIL2PS >::Encode(instr, is64_)); break;
            case I_VPERMILPD:           JITASM_ASSERT(encoder::Opcode$< I_VPERMILPD >::Encode(instr, is64_)); break;
            case I_VPERMILPS:           JITASM_ASSERT(encoder::Opcode$< I_VPERMILPS >::Encode(instr, is64_)); break;
            case I_VPERMPD:             JITASM_ASSERT(encoder::Opcode$< I_VPERMPD >::Encode(instr, is64_)); break;
            case I_VPERMPS:             JITASM_ASSERT(encoder::Opcode$< I_VPERMPS >::Encode(instr, is64_)); break;
            case I_VPERMQ:              JITASM_ASSERT(encoder::Opcode$< I_VPERMQ >::Encode(instr, is64_)); break;
            case I_VPERMT2D:            JITASM_ASSERT(encoder::Opcode$< I_VPERMT2D >::Encode(instr, is64_)); break;
            case I_VPERMT2PD:           JITASM_ASSERT(encoder::Opcode$< I_VPERMT2PD >::Encode(instr, is64_)); break;
            case I_VPERMT2PS:           JITASM_ASSERT(encoder::Opcode$< I_VPERMT2PS >::Encode(instr, is64_)); break;
            case I_VPERMT2Q:            JITASM_ASSERT(encoder::Opcode$< I_VPERMT2Q >::Encode(instr, is64_)); break;
            case I_VPEXTRB:             JITASM_ASSERT(encoder::Opcode$< I_VPEXTRB >::Encode(instr, is64_)); break;
            case I_VPEXTRD:             JITASM_ASSERT(encoder::Opcode$< I_VPEXTRD >::Encode(instr, is64_)); break;
            case I_VPEXTRQ:             JITASM_ASSERT(encoder::Opcode$< I_VPEXTRQ >::Encode(instr, is64_)); break;
            case I_VPEXTRW:             JITASM_ASSERT(encoder::Opcode$< I_VPEXTRW >::Encode(instr, is64_)); break;
            case I_VPGATHERDD:          JITASM_ASSERT(encoder::Opcode$< I_VPGATHERDD >::Encode(instr, is64_)); break;
            case I_VPGATHERDQ:          JITASM_ASSERT(encoder::Opcode$< I_VPGATHERDQ >::Encode(instr, is64_)); break;
            case I_VPGATHERQD:          JITASM_ASSERT(encoder::Opcode$< I_VPGATHERQD >::Encode(instr, is64_)); break;
            case I_VPGATHERQQ:          JITASM_ASSERT(encoder::Opcode$< I_VPGATHERQQ >::Encode(instr, is64_)); break;
            case I_VPHADDBD:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDBD >::Encode(instr, is64_)); break;
            case I_VPHADDBQ:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDBQ >::Encode(instr, is64_)); break;
            case I_VPHADDBW:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDBW >::Encode(instr, is64_)); break;
            case I_VPHADDD:             JITASM_ASSERT(encoder::Opcode$< I_VPHADDD >::Encode(instr, is64_)); break;
            case I_VPHADDDQ:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDDQ >::Encode(instr, is64_)); break;
            case I_VPHADDSW:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDSW >::Encode(instr, is64_)); break;
            case I_VPHADDUBD:           JITASM_ASSERT(encoder::Opcode$< I_VPHADDUBD >::Encode(instr, is64_)); break;
            case I_VPHADDUBQ:           JITASM_ASSERT(encoder::Opcode$< I_VPHADDUBQ >::Encode(instr, is64_)); break;
            case I_VPHADDUBW:           JITASM_ASSERT(encoder::Opcode$< I_VPHADDUBW >::Encode(instr, is64_)); break;
            case I_VPHADDUDQ:           JITASM_ASSERT(encoder::Opcode$< I_VPHADDUDQ >::Encode(instr, is64_)); break;
            case I_VPHADDUWD:           JITASM_ASSERT(encoder::Opcode$< I_VPHADDUWD >::Encode(instr, is64_)); break;
            case I_VPHADDUWQ:           JITASM_ASSERT(encoder::Opcode$< I_VPHADDUWQ >::Encode(instr, is64_)); break;
            case I_VPHADDW:             JITASM_ASSERT(encoder::Opcode$< I_VPHADDW >::Encode(instr, is64_)); break;
            case I_VPHADDWD:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDWD >::Encode(instr, is64_)); break;
            case I_VPHADDWQ:            JITASM_ASSERT(encoder::Opcode$< I_VPHADDWQ >::Encode(instr, is64_)); break;
            case I_VPHMINPOSUW:         JITASM_ASSERT(encoder::Opcode$< I_VPHMINPOSUW >::Encode(instr, is64_)); break;
            case I_VPHSUBBW:            JITASM_ASSERT(encoder::Opcode$< I_VPHSUBBW >::Encode(instr, is64_)); break;
            case I_VPHSUBD:             JITASM_ASSERT(encoder::Opcode$< I_VPHSUBD >::Encode(instr, is64_)); break;
            case I_VPHSUBDQ:            JITASM_ASSERT(encoder::Opcode$< I_VPHSUBDQ >::Encode(instr, is64_)); break;
            case I_VPHSUBSW:            JITASM_ASSERT(encoder::Opcode$< I_VPHSUBSW >::Encode(instr, is64_)); break;
            case I_VPHSUBW:             JITASM_ASSERT(encoder::Opcode$< I_VPHSUBW >::Encode(instr, is64_)); break;
            case I_VPHSUBWD:            JITASM_ASSERT(encoder::Opcode$< I_VPHSUBWD >::Encode(instr, is64_)); break;
            case I_VPINSRB:             JITASM_ASSERT(encoder::Opcode$< I_VPINSRB >::Encode(instr, is64_)); break;
            case I_VPINSRD:             JITASM_ASSERT(encoder::Opcode$< I_VPINSRD >::Encode(instr, is64_)); break;
            case I_VPINSRQ:             JITASM_ASSERT(encoder::Opcode$< I_VPINSRQ >::Encode(instr, is64_)); break;
            case I_VPINSRW:             JITASM_ASSERT(encoder::Opcode$< I_VPINSRW >::Encode(instr, is64_)); break;
            case I_VPLZCNTD:            JITASM_ASSERT(encoder::Opcode$< I_VPLZCNTD >::Encode(instr, is64_)); break;
            case I_VPLZCNTQ:            JITASM_ASSERT(encoder::Opcode$< I_VPLZCNTQ >::Encode(instr, is64_)); break;
            case I_VPMACSDD:            JITASM_ASSERT(encoder::Opcode$< I_VPMACSDD >::Encode(instr, is64_)); break;
            case I_VPMACSDQH:           JITASM_ASSERT(encoder::Opcode$< I_VPMACSDQH >::Encode(instr, is64_)); break;
            case I_VPMACSDQL:           JITASM_ASSERT(encoder::Opcode$< I_VPMACSDQL >::Encode(instr, is64_)); break;
            case I_VPMACSSDD:           JITASM_ASSERT(encoder::Opcode$< I_VPMACSSDD >::Encode(instr, is64_)); break;
            case I_VPMACSSDQH:          JITASM_ASSERT(encoder::Opcode$< I_VPMACSSDQH >::Encode(instr, is64_)); break;
            case I_VPMACSSDQL:          JITASM_ASSERT(encoder::Opcode$< I_VPMACSSDQL >::Encode(instr, is64_)); break;
            case I_VPMACSSWD:           JITASM_ASSERT(encoder::Opcode$< I_VPMACSSWD >::Encode(instr, is64_)); break;
            case I_VPMACSSWW:           JITASM_ASSERT(encoder::Opcode$< I_VPMACSSWW >::Encode(instr, is64_)); break;
            case I_VPMACSWD:            JITASM_ASSERT(encoder::Opcode$< I_VPMACSWD >::Encode(instr, is64_)); break;
            case I_VPMACSWW:            JITASM_ASSERT(encoder::Opcode$< I_VPMACSWW >::Encode(instr, is64_)); break;
            case I_VPMADCSSWD:          JITASM_ASSERT(encoder::Opcode$< I_VPMADCSSWD >::Encode(instr, is64_)); break;
            case I_VPMADCSWD:           JITASM_ASSERT(encoder::Opcode$< I_VPMADCSWD >::Encode(instr, is64_)); break;
            case I_VPMADDUBSW:          JITASM_ASSERT(encoder::Opcode$< I_VPMADDUBSW >::Encode(instr, is64_)); break;
            case I_VPMADDWD:            JITASM_ASSERT(encoder::Opcode$< I_VPMADDWD >::Encode(instr, is64_)); break;
            case I_VPMASKMOVD:          JITASM_ASSERT(encoder::Opcode$< I_VPMASKMOVD >::Encode(instr, is64_)); break;
            case I_VPMASKMOVQ:          JITASM_ASSERT(encoder::Opcode$< I_VPMASKMOVQ >::Encode(instr, is64_)); break;
            case I_VPMAXSB:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXSB >::Encode(instr, is64_)); break;
            case I_VPMAXSD:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXSD >::Encode(instr, is64_)); break;
            case I_VPMAXSQ:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXSQ >::Encode(instr, is64_)); break;
            case I_VPMAXSW:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXSW >::Encode(instr, is64_)); break;
            case I_VPMAXUB:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXUB >::Encode(instr, is64_)); break;
            case I_VPMAXUD:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXUD >::Encode(instr, is64_)); break;
            case I_VPMAXUQ:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXUQ >::Encode(instr, is64_)); break;
            case I_VPMAXUW:             JITASM_ASSERT(encoder::Opcode$< I_VPMAXUW >::Encode(instr, is64_)); break;
            case I_VPMINSB:             JITASM_ASSERT(encoder::Opcode$< I_VPMINSB >::Encode(instr, is64_)); break;
            case I_VPMINSD:             JITASM_ASSERT(encoder::Opcode$< I_VPMINSD >::Encode(instr, is64_)); break;
            case I_VPMINSQ:             JITASM_ASSERT(encoder::Opcode$< I_VPMINSQ >::Encode(instr, is64_)); break;
            case I_VPMINSW:             JITASM_ASSERT(encoder::Opcode$< I_VPMINSW >::Encode(instr, is64_)); break;
            case I_VPMINUB:             JITASM_ASSERT(encoder::Opcode$< I_VPMINUB >::Encode(instr, is64_)); break;
            case I_VPMINUD:             JITASM_ASSERT(encoder::Opcode$< I_VPMINUD >::Encode(instr, is64_)); break;
            case I_VPMINUQ:             JITASM_ASSERT(encoder::Opcode$< I_VPMINUQ >::Encode(instr, is64_)); break;
            case I_VPMINUW:             JITASM_ASSERT(encoder::Opcode$< I_VPMINUW >::Encode(instr, is64_)); break;
            case I_VPMOVDB:             JITASM_ASSERT(encoder::Opcode$< I_VPMOVDB >::Encode(instr, is64_)); break;
            case I_VPMOVDW:             JITASM_ASSERT(encoder::Opcode$< I_VPMOVDW >::Encode(instr, is64_)); break;
            case I_VPMOVMSKB:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVMSKB >::Encode(instr, is64_)); break;
            case I_VPMOVQB:             JITASM_ASSERT(encoder::Opcode$< I_VPMOVQB >::Encode(instr, is64_)); break;
            case I_VPMOVQD:             JITASM_ASSERT(encoder::Opcode$< I_VPMOVQD >::Encode(instr, is64_)); break;
            case I_VPMOVQW:             JITASM_ASSERT(encoder::Opcode$< I_VPMOVQW >::Encode(instr, is64_)); break;
            case I_VPMOVSDB:            JITASM_ASSERT(encoder::Opcode$< I_VPMOVSDB >::Encode(instr, is64_)); break;
            case I_VPMOVSDW:            JITASM_ASSERT(encoder::Opcode$< I_VPMOVSDW >::Encode(instr, is64_)); break;
            case I_VPMOVSQB:            JITASM_ASSERT(encoder::Opcode$< I_VPMOVSQB >::Encode(instr, is64_)); break;
            case I_VPMOVSQD:            JITASM_ASSERT(encoder::Opcode$< I_VPMOVSQD >::Encode(instr, is64_)); break;
            case I_VPMOVSQW:            JITASM_ASSERT(encoder::Opcode$< I_VPMOVSQW >::Encode(instr, is64_)); break;
            case I_VPMOVSXBD:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVSXBD >::Encode(instr, is64_)); break;
            case I_VPMOVSXBQ:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVSXBQ >::Encode(instr, is64_)); break;
            case I_VPMOVSXBW:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVSXBW >::Encode(instr, is64_)); break;
            case I_VPMOVSXDQ:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVSXDQ >::Encode(instr, is64_)); break;
            case I_VPMOVSXWD:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVSXWD >::Encode(instr, is64_)); break;
            case I_VPMOVSXWQ:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVSXWQ >::Encode(instr, is64_)); break;
            case I_VPMOVUSDB:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVUSDB >::Encode(instr, is64_)); break;
            case I_VPMOVUSDW:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVUSDW >::Encode(instr, is64_)); break;
            case I_VPMOVUSQB:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVUSQB >::Encode(instr, is64_)); break;
            case I_VPMOVUSQD:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVUSQD >::Encode(instr, is64_)); break;
            case I_VPMOVUSQW:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVUSQW >::Encode(instr, is64_)); break;
            case I_VPMOVZXBD:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVZXBD >::Encode(instr, is64_)); break;
            case I_VPMOVZXBQ:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVZXBQ >::Encode(instr, is64_)); break;
            case I_VPMOVZXBW:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVZXBW >::Encode(instr, is64_)); break;
            case I_VPMOVZXDQ:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVZXDQ >::Encode(instr, is64_)); break;
            case I_VPMOVZXWD:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVZXWD >::Encode(instr, is64_)); break;
            case I_VPMOVZXWQ:           JITASM_ASSERT(encoder::Opcode$< I_VPMOVZXWQ >::Encode(instr, is64_)); break;
            case I_VPMULDQ:             JITASM_ASSERT(encoder::Opcode$< I_VPMULDQ >::Encode(instr, is64_)); break;
            case I_VPMULHRSW:           JITASM_ASSERT(encoder::Opcode$< I_VPMULHRSW >::Encode(instr, is64_)); break;
            case I_VPMULHUW:            JITASM_ASSERT(encoder::Opcode$< I_VPMULHUW >::Encode(instr, is64_)); break;
            case I_VPMULHW:             JITASM_ASSERT(encoder::Opcode$< I_VPMULHW >::Encode(instr, is64_)); break;
            case I_VPMULLD:             JITASM_ASSERT(encoder::Opcode$< I_VPMULLD >::Encode(instr, is64_)); break;
            case I_VPMULLW:             JITASM_ASSERT(encoder::Opcode$< I_VPMULLW >::Encode(instr, is64_)); break;
            case I_VPMULUDQ:            JITASM_ASSERT(encoder::Opcode$< I_VPMULUDQ >::Encode(instr, is64_)); break;
            case I_VPOR:                JITASM_ASSERT(encoder::Opcode$< I_VPOR >::Encode(instr, is64_)); break;
            case I_VPORD:               JITASM_ASSERT(encoder::Opcode$< I_VPORD >::Encode(instr, is64_)); break;
            case I_VPORQ:               JITASM_ASSERT(encoder::Opcode$< I_VPORQ >::Encode(instr, is64_)); break;
            case I_VPPERM:              JITASM_ASSERT(encoder::Opcode$< I_VPPERM >::Encode(instr, is64_)); break;
            case I_VPROTB:              JITASM_ASSERT(encoder::Opcode$< I_VPROTB >::Encode(instr, is64_)); break;
            case I_VPROTD:              JITASM_ASSERT(encoder::Opcode$< I_VPROTD >::Encode(instr, is64_)); break;
            case I_VPROTQ:              JITASM_ASSERT(encoder::Opcode$< I_VPROTQ >::Encode(instr, is64_)); break;
            case I_VPROTW:              JITASM_ASSERT(encoder::Opcode$< I_VPROTW >::Encode(instr, is64_)); break;
            case I_VPSADBW:             JITASM_ASSERT(encoder::Opcode$< I_VPSADBW >::Encode(instr, is64_)); break;
            case I_VPSCATTERDD:         JITASM_ASSERT(encoder::Opcode$< I_VPSCATTERDD >::Encode(instr, is64_)); break;
            case I_VPSCATTERDQ:         JITASM_ASSERT(encoder::Opcode$< I_VPSCATTERDQ >::Encode(instr, is64_)); break;
            case I_VPSCATTERQD:         JITASM_ASSERT(encoder::Opcode$< I_VPSCATTERQD >::Encode(instr, is64_)); break;
            case I_VPSCATTERQQ:         JITASM_ASSERT(encoder::Opcode$< I_VPSCATTERQQ >::Encode(instr, is64_)); break;
            case I_VPSHAB:              JITASM_ASSERT(encoder::Opcode$< I_VPSHAB >::Encode(instr, is64_)); break;
            case I_VPSHAD:              JITASM_ASSERT(encoder::Opcode$< I_VPSHAD >::Encode(instr, is64_)); break;
            case I_VPSHAQ:              JITASM_ASSERT(encoder::Opcode$< I_VPSHAQ >::Encode(instr, is64_)); break;
            case I_VPSHAW:              JITASM_ASSERT(encoder::Opcode$< I_VPSHAW >::Encode(instr, is64_)); break;
            case I_VPSHLB:              JITASM_ASSERT(encoder::Opcode$< I_VPSHLB >::Encode(instr, is64_)); break;
            case I_VPSHLD:              JITASM_ASSERT(encoder::Opcode$< I_VPSHLD >::Encode(instr, is64_)); break;
            case I_VPSHLQ:              JITASM_ASSERT(encoder::Opcode$< I_VPSHLQ >::Encode(instr, is64_)); break;
            case I_VPSHLW:              JITASM_ASSERT(encoder::Opcode$< I_VPSHLW >::Encode(instr, is64_)); break;
            case I_VPSHUFB:             JITASM_ASSERT(encoder::Opcode$< I_VPSHUFB >::Encode(instr, is64_)); break;
            case I_VPSHUFD:             JITASM_ASSERT(encoder::Opcode$< I_VPSHUFD >::Encode(instr, is64_)); break;
            case I_VPSHUFHW:            JITASM_ASSERT(encoder::Opcode$< I_VPSHUFHW >::Encode(instr, is64_)); break;
            case I_VPSHUFLW:            JITASM_ASSERT(encoder::Opcode$< I_VPSHUFLW >::Encode(instr, is64_)); break;
            case I_VPSIGNB:             JITASM_ASSERT(encoder::Opcode$< I_VPSIGNB >::Encode(instr, is64_)); break;
            case I_VPSIGND:             JITASM_ASSERT(encoder::Opcode$< I_VPSIGND >::Encode(instr, is64_)); break;
            case I_VPSIGNW:             JITASM_ASSERT(encoder::Opcode$< I_VPSIGNW >::Encode(instr, is64_)); break;
            case I_VPSLLD:              JITASM_ASSERT(encoder::Opcode$< I_VPSLLD >::Encode(instr, is64_)); break;
            case I_VPSLLDQ:             JITASM_ASSERT(encoder::Opcode$< I_VPSLLDQ >::Encode(instr, is64_)); break;
            case I_VPSLLQ:              JITASM_ASSERT(encoder::Opcode$< I_VPSLLQ >::Encode(instr, is64_)); break;
            case I_VPSLLVD:             JITASM_ASSERT(encoder::Opcode$< I_VPSLLVD >::Encode(instr, is64_)); break;
            case I_VPSLLVQ:             JITASM_ASSERT(encoder::Opcode$< I_VPSLLVQ >::Encode(instr, is64_)); break;
            case I_VPSLLW:              JITASM_ASSERT(encoder::Opcode$< I_VPSLLW >::Encode(instr, is64_)); break;
            case I_VPSRAD:              JITASM_ASSERT(encoder::Opcode$< I_VPSRAD >::Encode(instr, is64_)); break;
            case I_VPSRAQ:              JITASM_ASSERT(encoder::Opcode$< I_VPSRAQ >::Encode(instr, is64_)); break;
            case I_VPSRAVD:             JITASM_ASSERT(encoder::Opcode$< I_VPSRAVD >::Encode(instr, is64_)); break;
            case I_VPSRAVQ:             JITASM_ASSERT(encoder::Opcode$< I_VPSRAVQ >::Encode(instr, is64_)); break;
            case I_VPSRAW:              JITASM_ASSERT(encoder::Opcode$< I_VPSRAW >::Encode(instr, is64_)); break;
            case I_VPSRLD:              JITASM_ASSERT(encoder::Opcode$< I_VPSRLD >::Encode(instr, is64_)); break;
            case I_VPSRLDQ:             JITASM_ASSERT(encoder::Opcode$< I_VPSRLDQ >::Encode(instr, is64_)); break;
            case I_VPSRLQ:              JITASM_ASSERT(encoder::Opcode$< I_VPSRLQ >::Encode(instr, is64_)); break;
            case I_VPSRLVD:             JITASM_ASSERT(encoder::Opcode$< I_VPSRLVD >::Encode(instr, is64_)); break;
            case I_VPSRLVQ:             JITASM_ASSERT(encoder::Opcode$< I_VPSRLVQ >::Encode(instr, is64_)); break;
            case I_VPSRLW:              JITASM_ASSERT(encoder::Opcode$< I_VPSRLW >::Encode(instr, is64_)); break;
            case I_VPSUBB:              JITASM_ASSERT(encoder::Opcode$< I_VPSUBB >::Encode(instr, is64_)); break;
            case I_VPSUBD:              JITASM_ASSERT(encoder::Opcode$< I_VPSUBD >::Encode(instr, is64_)); break;
            case I_VPSUBQ:              JITASM_ASSERT(encoder::Opcode$< I_VPSUBQ >::Encode(instr, is64_)); break;
            case I_VPSUBSB:             JITASM_ASSERT(encoder::Opcode$< I_VPSUBSB >::Encode(instr, is64_)); break;
            case I_VPSUBSW:             JITASM_ASSERT(encoder::Opcode$< I_VPSUBSW >::Encode(instr, is64_)); break;
            case I_VPSUBUSB:            JITASM_ASSERT(encoder::Opcode$< I_VPSUBUSB >::Encode(instr, is64_)); break;
            case I_VPSUBUSW:            JITASM_ASSERT(encoder::Opcode$< I_VPSUBUSW >::Encode(instr, is64_)); break;
            case I_VPSUBW:              JITASM_ASSERT(encoder::Opcode$< I_VPSUBW >::Encode(instr, is64_)); break;
            case I_VPTEST:              JITASM_ASSERT(encoder::Opcode$< I_VPTEST >::Encode(instr, is64_)); break;
            case I_VPTESTMD:            JITASM_ASSERT(encoder::Opcode$< I_VPTESTMD >::Encode(instr, is64_)); break;
            case I_VPTESTMQ:            JITASM_ASSERT(encoder::Opcode$< I_VPTESTMQ >::Encode(instr, is64_)); break;
            case I_VPTESTNMD:           JITASM_ASSERT(encoder::Opcode$< I_VPTESTNMD >::Encode(instr, is64_)); break;
            case I_VPTESTNMQ:           JITASM_ASSERT(encoder::Opcode$< I_VPTESTNMQ >::Encode(instr, is64_)); break;
            case I_VPUNPCKHBW:          JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKHBW >::Encode(instr, is64_)); break;
            case I_VPUNPCKHDQ:          JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKHDQ >::Encode(instr, is64_)); break;
            case I_VPUNPCKHQDQ:         JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKHQDQ >::Encode(instr, is64_)); break;
            case I_VPUNPCKHWD:          JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKHWD >::Encode(instr, is64_)); break;
            case I_VPUNPCKLBW:          JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKLBW >::Encode(instr, is64_)); break;
            case I_VPUNPCKLDQ:          JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKLDQ >::Encode(instr, is64_)); break;
            case I_VPUNPCKLQDQ:         JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKLQDQ >::Encode(instr, is64_)); break;
            case I_VPUNPCKLWD:          JITASM_ASSERT(encoder::Opcode$< I_VPUNPCKLWD >::Encode(instr, is64_)); break;
            case I_VPXOR:               JITASM_ASSERT(encoder::Opcode$< I_VPXOR >::Encode(instr, is64_)); break;
            case I_VPXORD:              JITASM_ASSERT(encoder::Opcode$< I_VPXORD >::Encode(instr, is64_)); break;
            case I_VPXORQ:              JITASM_ASSERT(encoder::Opcode$< I_VPXORQ >::Encode(instr, is64_)); break;
            case I_VRCP14PD:            JITASM_ASSERT(encoder::Opcode$< I_VRCP14PD >::Encode(instr, is64_)); break;
            case I_VRCP14PS:            JITASM_ASSERT(encoder::Opcode$< I_VRCP14PS >::Encode(instr, is64_)); break;
            case I_VRCP14SD:            JITASM_ASSERT(encoder::Opcode$< I_VRCP14SD >::Encode(instr, is64_)); break;
            case I_VRCP14SS:            JITASM_ASSERT(encoder::Opcode$< I_VRCP14SS >::Encode(instr, is64_)); break;
            case I_VRCP28PD:            JITASM_ASSERT(encoder::Opcode$< I_VRCP28PD >::Encode(instr, is64_)); break;
            case I_VRCP28PS:            JITASM_ASSERT(encoder::Opcode$< I_VRCP28PS >::Encode(instr, is64_)); break;
            case I_VRCP28SD:            JITASM_ASSERT(encoder::Opcode$< I_VRCP28SD >::Encode(instr, is64_)); break;
            case I_VRCP28SS:            JITASM_ASSERT(encoder::Opcode$< I_VRCP28SS >::Encode(instr, is64_)); break;
            case I_VRCPPS:              JITASM_ASSERT(encoder::Opcode$< I_VRCPPS >::Encode(instr, is64_)); break;
            case I_VRCPSS:              JITASM_ASSERT(encoder::Opcode$< I_VRCPSS >::Encode(instr, is64_)); break;
            case I_VRNDSCALEPD:         JITASM_ASSERT(encoder::Opcode$< I_VRNDSCALEPD >::Encode(instr, is64_)); break;
            case I_VRNDSCALEPS:         JITASM_ASSERT(encoder::Opcode$< I_VRNDSCALEPS >::Encode(instr, is64_)); break;
            case I_VRNDSCALESD:         JITASM_ASSERT(encoder::Opcode$< I_VRNDSCALESD >::Encode(instr, is64_)); break;
            case I_VRNDSCALESS:         JITASM_ASSERT(encoder::Opcode$< I_VRNDSCALESS >::Encode(instr, is64_)); break;
            case I_VROUNDPD:            JITASM_ASSERT(encoder::Opcode$< I_VROUNDPD >::Encode(instr, is64_)); break;
            case I_VROUNDPS:            JITASM_ASSERT(encoder::Opcode$< I_VROUNDPS >::Encode(instr, is64_)); break;
            case I_VROUNDSD:            JITASM_ASSERT(encoder::Opcode$< I_VROUNDSD >::Encode(instr, is64_)); break;
            case I_VROUNDSS:            JITASM_ASSERT(encoder::Opcode$< I_VROUNDSS >::Encode(instr, is64_)); break;
            case I_VRSQRT14PD:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT14PD >::Encode(instr, is64_)); break;
            case I_VRSQRT14PS:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT14PS >::Encode(instr, is64_)); break;
            case I_VRSQRT14SD:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT14SD >::Encode(instr, is64_)); break;
            case I_VRSQRT14SS:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT14SS >::Encode(instr, is64_)); break;
            case I_VRSQRT28PD:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT28PD >::Encode(instr, is64_)); break;
            case I_VRSQRT28PS:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT28PS >::Encode(instr, is64_)); break;
            case I_VRSQRT28SD:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT28SD >::Encode(instr, is64_)); break;
            case I_VRSQRT28SS:          JITASM_ASSERT(encoder::Opcode$< I_VRSQRT28SS >::Encode(instr, is64_)); break;
            case I_VRSQRTPS:            JITASM_ASSERT(encoder::Opcode$< I_VRSQRTPS >::Encode(instr, is64_)); break;
            case I_VRSQRTSS:            JITASM_ASSERT(encoder::Opcode$< I_VRSQRTSS >::Encode(instr, is64_)); break;
            case I_VSCATTERDPD:         JITASM_ASSERT(encoder::Opcode$< I_VSCATTERDPD >::Encode(instr, is64_)); break;
            case I_VSCATTERDPS:         JITASM_ASSERT(encoder::Opcode$< I_VSCATTERDPS >::Encode(instr, is64_)); break;
            case I_VSCATTERPF0DPD:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF0DPD >::Encode(instr, is64_)); break;
            case I_VSCATTERPF0DPS:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF0DPS >::Encode(instr, is64_)); break;
            case I_VSCATTERPF0QPD:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF0QPD >::Encode(instr, is64_)); break;
            case I_VSCATTERPF0QPS:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF0QPS >::Encode(instr, is64_)); break;
            case I_VSCATTERPF1DPD:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF1DPD >::Encode(instr, is64_)); break;
            case I_VSCATTERPF1DPS:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF1DPS >::Encode(instr, is64_)); break;
            case I_VSCATTERPF1QPD:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF1QPD >::Encode(instr, is64_)); break;
            case I_VSCATTERPF1QPS:      JITASM_ASSERT(encoder::Opcode$< I_VSCATTERPF1QPS >::Encode(instr, is64_)); break;
            case I_VSCATTERQPD:         JITASM_ASSERT(encoder::Opcode$< I_VSCATTERQPD >::Encode(instr, is64_)); break;
            case I_VSCATTERQPS:         JITASM_ASSERT(encoder::Opcode$< I_VSCATTERQPS >::Encode(instr, is64_)); break;
            case I_VSHUFPD:             JITASM_ASSERT(encoder::Opcode$< I_VSHUFPD >::Encode(instr, is64_)); break;
            case I_VSHUFPS:             JITASM_ASSERT(encoder::Opcode$< I_VSHUFPS >::Encode(instr, is64_)); break;
            case I_VSQRTPD:             JITASM_ASSERT(encoder::Opcode$< I_VSQRTPD >::Encode(instr, is64_)); break;
            case I_VSQRTPS:             JITASM_ASSERT(encoder::Opcode$< I_VSQRTPS >::Encode(instr, is64_)); break;
            case I_VSQRTSD:             JITASM_ASSERT(encoder::Opcode$< I_VSQRTSD >::Encode(instr, is64_)); break;
            case I_VSQRTSS:             JITASM_ASSERT(encoder::Opcode$< I_VSQRTSS >::Encode(instr, is64_)); break;
            case I_VSTMXCSR:            JITASM_ASSERT(encoder::Opcode$< I_VSTMXCSR >::Encode(instr, is64_)); break;
            case I_VSUBPD:              JITASM_ASSERT(encoder::Opcode$< I_VSUBPD >::Encode(instr, is64_)); break;
            case I_VSUBPS:              JITASM_ASSERT(encoder::Opcode$< I_VSUBPS >::Encode(instr, is64_)); break;
            case I_VSUBSD:              JITASM_ASSERT(encoder::Opcode$< I_VSUBSD >::Encode(instr, is64_)); break;
            case I_VSUBSS:              JITASM_ASSERT(encoder::Opcode$< I_VSUBSS >::Encode(instr, is64_)); break;
            case I_VTESTPD:             JITASM_ASSERT(encoder::Opcode$< I_VTESTPD >::Encode(instr, is64_)); break;
            case I_VTESTPS:             JITASM_ASSERT(encoder::Opcode$< I_VTESTPS >::Encode(instr, is64_)); break;
            case I_VUCOMISD:            JITASM_ASSERT(encoder::Opcode$< I_VUCOMISD >::Encode(instr, is64_)); break;
            case I_VUCOMISS:            JITASM_ASSERT(encoder::Opcode$< I_VUCOMISS >::Encode(instr, is64_)); break;
            case I_VUNPCKHPD:           JITASM_ASSERT(encoder::Opcode$< I_VUNPCKHPD >::Encode(instr, is64_)); break;
            case I_VUNPCKHPS:           JITASM_ASSERT(encoder::Opcode$< I_VUNPCKHPS >::Encode(instr, is64_)); break;
            case I_VUNPCKLPD:           JITASM_ASSERT(encoder::Opcode$< I_VUNPCKLPD >::Encode(instr, is64_)); break;
            case I_VUNPCKLPS:           JITASM_ASSERT(encoder::Opcode$< I_VUNPCKLPS >::Encode(instr, is64_)); break;
            case I_VXORPD:              JITASM_ASSERT(encoder::Opcode$< I_VXORPD >::Encode(instr, is64_)); break;
            case I_VXORPS:              JITASM_ASSERT(encoder::Opcode$< I_VXORPS >::Encode(instr, is64_)); break;
            case I_VZEROALL:            JITASM_ASSERT(encoder::Opcode$< I_VZEROALL >::Encode(instr, is64_)); break;
            case I_VZEROUPPER:          JITASM_ASSERT(encoder::Opcode$< I_VZEROUPPER >::Encode(instr, is64_)); break;
            case I_WAIT:                JITASM_ASSERT(encoder::Opcode$< I_WAIT >::Encode(instr, is64_)); break;
            case I_WBINVD:              JITASM_ASSERT(encoder::Opcode$< I_WBINVD >::Encode(instr, is64_)); break;
            case I_WRFSBASE:            JITASM_ASSERT(encoder::Opcode$< I_WRFSBASE >::Encode(instr, is64_)); break;
            case I_WRGSBASE:            JITASM_ASSERT(encoder::Opcode$< I_WRGSBASE >::Encode(instr, is64_)); break;
            case I_WRMSR:               JITASM_ASSERT(encoder::Opcode$< I_WRMSR >::Encode(instr, is64_)); break;
            case I_XABORT:              JITASM_ASSERT(encoder::Opcode$< I_XABORT >::Encode(instr, is64_)); break;
            case I_XACQUIRE:            JITASM_ASSERT(encoder::Opcode$< I_XACQUIRE >::Encode(instr, is64_)); break;
            case I_XADD:                JITASM_ASSERT(encoder::Opcode$< I_XADD >::Encode(instr, is64_)); break;
            case I_XBEGIN:              JITASM_ASSERT(encoder::Opcode$< I_XBEGIN >::Encode(instr, is64_)); break;
            case I_XCHG:                JITASM_ASSERT(encoder::Opcode$< I_XCHG >::Encode(instr, is64_)); break;
            case I_XCRYPTCBC:           JITASM_ASSERT(encoder::Opcode$< I_XCRYPTCBC >::Encode(instr, is64_)); break;
            case I_XCRYPTCFB:           JITASM_ASSERT(encoder::Opcode$< I_XCRYPTCFB >::Encode(instr, is64_)); break;
            case I_XCRYPTCTR:           JITASM_ASSERT(encoder::Opcode$< I_XCRYPTCTR >::Encode(instr, is64_)); break;
            case I_XCRYPTECB:           JITASM_ASSERT(encoder::Opcode$< I_XCRYPTECB >::Encode(instr, is64_)); break;
            case I_XCRYPTOFB:           JITASM_ASSERT(encoder::Opcode$< I_XCRYPTOFB >::Encode(instr, is64_)); break;
            case I_XEND:                JITASM_ASSERT(encoder::Opcode$< I_XEND >::Encode(instr, is64_)); break;
            case I_XGETBV:              JITASM_ASSERT(encoder::Opcode$< I_XGETBV >::Encode(instr, is64_)); break;
            case I_XLATB:               JITASM_ASSERT(encoder::Opcode$< I_XLATB >::Encode(instr, is64_)); break;
            case I_XOR:                 JITASM_ASSERT(encoder::Opcode$< I_XOR >::Encode(instr, is64_)); break;
            case I_XORPD:               JITASM_ASSERT(encoder::Opcode$< I_XORPD >::Encode(instr, is64_)); break;
            case I_XORPS:               JITASM_ASSERT(encoder::Opcode$< I_XORPS >::Encode(instr, is64_)); break;
            case I_XRELEASE:            JITASM_ASSERT(encoder::Opcode$< I_XRELEASE >::Encode(instr, is64_)); break;
            case I_XRSTOR:              JITASM_ASSERT(encoder::Opcode$< I_XRSTOR >::Encode(instr, is64_)); break;
            case I_XRSTOR64:            JITASM_ASSERT(encoder::Opcode$< I_XRSTOR64 >::Encode(instr, is64_)); break;
            case I_XSAVE:               JITASM_ASSERT(encoder::Opcode$< I_XSAVE >::Encode(instr, is64_)); break;
            case I_XSAVE64:             JITASM_ASSERT(encoder::Opcode$< I_XSAVE64 >::Encode(instr, is64_)); break;
            case I_XSAVEOPT:            JITASM_ASSERT(encoder::Opcode$< I_XSAVEOPT >::Encode(instr, is64_)); break;
            case I_XSAVEOPT64:          JITASM_ASSERT(encoder::Opcode$< I_XSAVEOPT64 >::Encode(instr, is64_)); break;
            case I_XSETBV:              JITASM_ASSERT(encoder::Opcode$< I_XSETBV >::Encode(instr, is64_)); break;
            case I_XSHA1:               JITASM_ASSERT(encoder::Opcode$< I_XSHA1 >::Encode(instr, is64_)); break;
            case I_XSHA256:             JITASM_ASSERT(encoder::Opcode$< I_XSHA256 >::Encode(instr, is64_)); break;
            case I_XSTORE:              JITASM_ASSERT(encoder::Opcode$< I_XSTORE >::Encode(instr, is64_)); break;
            case I_XTEST:               JITASM_ASSERT(encoder::Opcode$< I_XTEST >::Encode(instr, is64_)); break;
            default:                    JITASM_ASSERT(0 && "unknown instruction");
            }
        }

#ifdef JITASM_TEST
        void Backend::TestInstr(InstrID id, std::vector< Instr > & list, bool is64)
        {
            switch (id)
            {
            case I_AAA:                 encoder::Opcode$< I_AAA >::Test(list, is64); break;
            case I_AAD:                 encoder::Opcode$< I_AAD >::Test(list, is64); break;
            case I_AAM:                 encoder::Opcode$< I_AAM >::Test(list, is64); break;
            case I_AAS:                 encoder::Opcode$< I_AAS >::Test(list, is64); break;
            case I_ADC:                 encoder::Opcode$< I_ADC >::Test(list, is64); break;
            case I_ADCX:                encoder::Opcode$< I_ADCX >::Test(list, is64); break;
            case I_ADD:                 encoder::Opcode$< I_ADD >::Test(list, is64); break;
            case I_ADDPD:               encoder::Opcode$< I_ADDPD >::Test(list, is64); break;
            case I_ADDPS:               encoder::Opcode$< I_ADDPS >::Test(list, is64); break;
            case I_ADDSD:               encoder::Opcode$< I_ADDSD >::Test(list, is64); break;
            case I_ADDSS:               encoder::Opcode$< I_ADDSS >::Test(list, is64); break;
            case I_ADDSUBPD:            encoder::Opcode$< I_ADDSUBPD >::Test(list, is64); break;
            case I_ADDSUBPS:            encoder::Opcode$< I_ADDSUBPS >::Test(list, is64); break;
            case I_ADOX:                encoder::Opcode$< I_ADOX >::Test(list, is64); break;
            case I_AESDEC:              encoder::Opcode$< I_AESDEC >::Test(list, is64); break;
            case I_AESDECLAST:          encoder::Opcode$< I_AESDECLAST >::Test(list, is64); break;
            case I_AESENC:              encoder::Opcode$< I_AESENC >::Test(list, is64); break;
            case I_AESENCLAST:          encoder::Opcode$< I_AESENCLAST >::Test(list, is64); break;
            case I_AESIMC:              encoder::Opcode$< I_AESIMC >::Test(list, is64); break;
            case I_AESKEYGENASSIST:     encoder::Opcode$< I_AESKEYGENASSIST >::Test(list, is64); break;
            case I_AND:                 encoder::Opcode$< I_AND >::Test(list, is64); break;
            case I_ANDN:                encoder::Opcode$< I_ANDN >::Test(list, is64); break;
            case I_ANDNPD:              encoder::Opcode$< I_ANDNPD >::Test(list, is64); break;
            case I_ANDNPS:              encoder::Opcode$< I_ANDNPS >::Test(list, is64); break;
            case I_ANDPD:               encoder::Opcode$< I_ANDPD >::Test(list, is64); break;
            case I_ANDPS:               encoder::Opcode$< I_ANDPS >::Test(list, is64); break;
            case I_ARPL:                encoder::Opcode$< I_ARPL >::Test(list, is64); break;
            case I_BEXTR:               encoder::Opcode$< I_BEXTR >::Test(list, is64); break;
            case I_BLCFILL:             encoder::Opcode$< I_BLCFILL >::Test(list, is64); break;
            case I_BLCI:                encoder::Opcode$< I_BLCI >::Test(list, is64); break;
            case I_BLCIC:               encoder::Opcode$< I_BLCIC >::Test(list, is64); break;
            case I_BLCMSK:              encoder::Opcode$< I_BLCMSK >::Test(list, is64); break;
            case I_BLCS:                encoder::Opcode$< I_BLCS >::Test(list, is64); break;
            case I_BLENDPD:             encoder::Opcode$< I_BLENDPD >::Test(list, is64); break;
            case I_BLENDPS:             encoder::Opcode$< I_BLENDPS >::Test(list, is64); break;
            case I_BLENDVPD:            encoder::Opcode$< I_BLENDVPD >::Test(list, is64); break;
            case I_BLENDVPS:            encoder::Opcode$< I_BLENDVPS >::Test(list, is64); break;
            case I_BLSFILL:             encoder::Opcode$< I_BLSFILL >::Test(list, is64); break;
            case I_BLSI:                encoder::Opcode$< I_BLSI >::Test(list, is64); break;
            case I_BLSIC:               encoder::Opcode$< I_BLSIC >::Test(list, is64); break;
            case I_BLSMSK:              encoder::Opcode$< I_BLSMSK >::Test(list, is64); break;
            case I_BLSR:                encoder::Opcode$< I_BLSR >::Test(list, is64); break;
            case I_BOUND:               encoder::Opcode$< I_BOUND >::Test(list, is64); break;
            case I_BSF:                 encoder::Opcode$< I_BSF >::Test(list, is64); break;
            case I_BSR:                 encoder::Opcode$< I_BSR >::Test(list, is64); break;
            case I_BSWAP:               encoder::Opcode$< I_BSWAP >::Test(list, is64); break;
            case I_BT:                  encoder::Opcode$< I_BT >::Test(list, is64); break;
            case I_BTC:                 encoder::Opcode$< I_BTC >::Test(list, is64); break;
            case I_BTR:                 encoder::Opcode$< I_BTR >::Test(list, is64); break;
            case I_BTS:                 encoder::Opcode$< I_BTS >::Test(list, is64); break;
            case I_BZHI:                encoder::Opcode$< I_BZHI >::Test(list, is64); break;
            case I_CALL:                encoder::Opcode$< I_CALL >::Test(list, is64); break;
            case I_CBW:                 encoder::Opcode$< I_CBW >::Test(list, is64); break;
            case I_CDQ:                 encoder::Opcode$< I_CDQ >::Test(list, is64); break;
            case I_CDQE:                encoder::Opcode$< I_CDQE >::Test(list, is64); break;
            case I_CLAC:                encoder::Opcode$< I_CLAC >::Test(list, is64); break;
            case I_CLC:                 encoder::Opcode$< I_CLC >::Test(list, is64); break;
            case I_CLD:                 encoder::Opcode$< I_CLD >::Test(list, is64); break;
            case I_CLFLUSH:             encoder::Opcode$< I_CLFLUSH >::Test(list, is64); break;
            case I_CLGI:                encoder::Opcode$< I_CLGI >::Test(list, is64); break;
            case I_CLI:                 encoder::Opcode$< I_CLI >::Test(list, is64); break;
            case I_CLTS:                encoder::Opcode$< I_CLTS >::Test(list, is64); break;
            case I_CMC:                 encoder::Opcode$< I_CMC >::Test(list, is64); break;
            case I_CMOVcc:              encoder::Opcode$< I_CMOVcc >::Test(list, is64); break;
            case I_CMP:                 encoder::Opcode$< I_CMP >::Test(list, is64); break;
            case I_CMPPD:               encoder::Opcode$< I_CMPPD >::Test(list, is64); break;
            case I_CMPPS:               encoder::Opcode$< I_CMPPS >::Test(list, is64); break;
            case I_CMPS:                encoder::Opcode$< I_CMPS >::Test(list, is64); break;
            case I_CMPSD:               encoder::Opcode$< I_CMPSD >::Test(list, is64); break;
            case I_CMPSS:               encoder::Opcode$< I_CMPSS >::Test(list, is64); break;
            case I_CMPXCHG:             encoder::Opcode$< I_CMPXCHG >::Test(list, is64); break;
            case I_CMPXCHG16B:          encoder::Opcode$< I_CMPXCHG16B >::Test(list, is64); break;
            case I_CMPXCHG8B:           encoder::Opcode$< I_CMPXCHG8B >::Test(list, is64); break;
            case I_COMISD:              encoder::Opcode$< I_COMISD >::Test(list, is64); break;
            case I_COMISS:              encoder::Opcode$< I_COMISS >::Test(list, is64); break;
            case I_CPUID:               encoder::Opcode$< I_CPUID >::Test(list, is64); break;
            case I_CQO:                 encoder::Opcode$< I_CQO >::Test(list, is64); break;
            case I_CRC32:               encoder::Opcode$< I_CRC32 >::Test(list, is64); break;
            case I_CVTDQ2PD:            encoder::Opcode$< I_CVTDQ2PD >::Test(list, is64); break;
            case I_CVTDQ2PS:            encoder::Opcode$< I_CVTDQ2PS >::Test(list, is64); break;
            case I_CVTPD2DQ:            encoder::Opcode$< I_CVTPD2DQ >::Test(list, is64); break;
            case I_CVTPD2PI:            encoder::Opcode$< I_CVTPD2PI >::Test(list, is64); break;
            case I_CVTPD2PS:            encoder::Opcode$< I_CVTPD2PS >::Test(list, is64); break;
            case I_CVTPI2PD:            encoder::Opcode$< I_CVTPI2PD >::Test(list, is64); break;
            case I_CVTPI2PS:            encoder::Opcode$< I_CVTPI2PS >::Test(list, is64); break;
            case I_CVTPS2DQ:            encoder::Opcode$< I_CVTPS2DQ >::Test(list, is64); break;
            case I_CVTPS2PD:            encoder::Opcode$< I_CVTPS2PD >::Test(list, is64); break;
            case I_CVTPS2PI:            encoder::Opcode$< I_CVTPS2PI >::Test(list, is64); break;
            case I_CVTSD2SI:            encoder::Opcode$< I_CVTSD2SI >::Test(list, is64); break;
            case I_CVTSD2SS:            encoder::Opcode$< I_CVTSD2SS >::Test(list, is64); break;
            case I_CVTSI2SD:            encoder::Opcode$< I_CVTSI2SD >::Test(list, is64); break;
            case I_CVTSI2SS:            encoder::Opcode$< I_CVTSI2SS >::Test(list, is64); break;
            case I_CVTSS2SD:            encoder::Opcode$< I_CVTSS2SD >::Test(list, is64); break;
            case I_CVTSS2SI:            encoder::Opcode$< I_CVTSS2SI >::Test(list, is64); break;
            case I_CVTTPD2DQ:           encoder::Opcode$< I_CVTTPD2DQ >::Test(list, is64); break;
            case I_CVTTPD2PI:           encoder::Opcode$< I_CVTTPD2PI >::Test(list, is64); break;
            case I_CVTTPS2DQ:           encoder::Opcode$< I_CVTTPS2DQ >::Test(list, is64); break;
            case I_CVTTPS2PI:           encoder::Opcode$< I_CVTTPS2PI >::Test(list, is64); break;
            case I_CVTTSD2SI:           encoder::Opcode$< I_CVTTSD2SI >::Test(list, is64); break;
            case I_CVTTSS2SI:           encoder::Opcode$< I_CVTTSS2SI >::Test(list, is64); break;
            case I_CWD:                 encoder::Opcode$< I_CWD >::Test(list, is64); break;
            case I_CWDE:                encoder::Opcode$< I_CWDE >::Test(list, is64); break;
            case I_DAA:                 encoder::Opcode$< I_DAA >::Test(list, is64); break;
            case I_DAS:                 encoder::Opcode$< I_DAS >::Test(list, is64); break;
            case I_DATA16:              encoder::Opcode$< I_DATA16 >::Test(list, is64); break;
            case I_DEC:                 encoder::Opcode$< I_DEC >::Test(list, is64); break;
            case I_DIV:                 encoder::Opcode$< I_DIV >::Test(list, is64); break;
            case I_DIVPD:               encoder::Opcode$< I_DIVPD >::Test(list, is64); break;
            case I_DIVPS:               encoder::Opcode$< I_DIVPS >::Test(list, is64); break;
            case I_DIVSD:               encoder::Opcode$< I_DIVSD >::Test(list, is64); break;
            case I_DIVSS:               encoder::Opcode$< I_DIVSS >::Test(list, is64); break;
            case I_DPPD:                encoder::Opcode$< I_DPPD >::Test(list, is64); break;
            case I_DPPS:                encoder::Opcode$< I_DPPS >::Test(list, is64); break;
            case I_EMMS:                encoder::Opcode$< I_EMMS >::Test(list, is64); break;
            case I_ENCLS:               encoder::Opcode$< I_ENCLS >::Test(list, is64); break;
            case I_ENCLU:               encoder::Opcode$< I_ENCLU >::Test(list, is64); break;
            case I_ENTER:               encoder::Opcode$< I_ENTER >::Test(list, is64); break;
            case I_EXTRACTPS:           encoder::Opcode$< I_EXTRACTPS >::Test(list, is64); break;
            case I_EXTRQ:               encoder::Opcode$< I_EXTRQ >::Test(list, is64); break;
            case I_F2XM1:               encoder::Opcode$< I_F2XM1 >::Test(list, is64); break;
            case I_FABS:                encoder::Opcode$< I_FABS >::Test(list, is64); break;
            case I_FADD:                encoder::Opcode$< I_FADD >::Test(list, is64); break;
            case I_FADDP:               encoder::Opcode$< I_FADDP >::Test(list, is64); break;
            case I_FBLD:                encoder::Opcode$< I_FBLD >::Test(list, is64); break;
            case I_FBSTP:               encoder::Opcode$< I_FBSTP >::Test(list, is64); break;
            case I_FCHS:                encoder::Opcode$< I_FCHS >::Test(list, is64); break;
            case I_FCMOVcc:             encoder::Opcode$< I_FCMOVcc >::Test(list, is64); break;
            case I_FCOM:                encoder::Opcode$< I_FCOM >::Test(list, is64); break;
            case I_FCOMI:               encoder::Opcode$< I_FCOMI >::Test(list, is64); break;
            case I_FCOMP:               encoder::Opcode$< I_FCOMP >::Test(list, is64); break;
            case I_FCOMPI:              encoder::Opcode$< I_FCOMPI >::Test(list, is64); break;
            case I_FCOMPP:              encoder::Opcode$< I_FCOMPP >::Test(list, is64); break;
            case I_FCOS:                encoder::Opcode$< I_FCOS >::Test(list, is64); break;
            case I_FDECSTP:             encoder::Opcode$< I_FDECSTP >::Test(list, is64); break;
            case I_FDIV:                encoder::Opcode$< I_FDIV >::Test(list, is64); break;
            case I_FDIVP:               encoder::Opcode$< I_FDIVP >::Test(list, is64); break;
            case I_FDIVR:               encoder::Opcode$< I_FDIVR >::Test(list, is64); break;
            case I_FDIVRP:              encoder::Opcode$< I_FDIVRP >::Test(list, is64); break;
            case I_FEMMS:               encoder::Opcode$< I_FEMMS >::Test(list, is64); break;
            case I_FFREE:               encoder::Opcode$< I_FFREE >::Test(list, is64); break;
            case I_FIADD:               encoder::Opcode$< I_FIADD >::Test(list, is64); break;
            case I_FICOM:               encoder::Opcode$< I_FICOM >::Test(list, is64); break;
            case I_FICOMP:              encoder::Opcode$< I_FICOMP >::Test(list, is64); break;
            case I_FIDIV:               encoder::Opcode$< I_FIDIV >::Test(list, is64); break;
            case I_FIDIVR:              encoder::Opcode$< I_FIDIVR >::Test(list, is64); break;
            case I_FILD:                encoder::Opcode$< I_FILD >::Test(list, is64); break;
            case I_FIMUL:               encoder::Opcode$< I_FIMUL >::Test(list, is64); break;
            case I_FINCSTP:             encoder::Opcode$< I_FINCSTP >::Test(list, is64); break;
            case I_FIST:                encoder::Opcode$< I_FIST >::Test(list, is64); break;
            case I_FISTP:               encoder::Opcode$< I_FISTP >::Test(list, is64); break;
            case I_FISTTP:              encoder::Opcode$< I_FISTTP >::Test(list, is64); break;
            case I_FISUB:               encoder::Opcode$< I_FISUB >::Test(list, is64); break;
            case I_FISUBR:              encoder::Opcode$< I_FISUBR >::Test(list, is64); break;
            case I_FLD:                 encoder::Opcode$< I_FLD >::Test(list, is64); break;
            case I_FLD1:                encoder::Opcode$< I_FLD1 >::Test(list, is64); break;
            case I_FLDCW:               encoder::Opcode$< I_FLDCW >::Test(list, is64); break;
            case I_FLDENV:              encoder::Opcode$< I_FLDENV >::Test(list, is64); break;
            case I_FLDL2E:              encoder::Opcode$< I_FLDL2E >::Test(list, is64); break;
            case I_FLDL2T:              encoder::Opcode$< I_FLDL2T >::Test(list, is64); break;
            case I_FLDLG2:              encoder::Opcode$< I_FLDLG2 >::Test(list, is64); break;
            case I_FLDLN2:              encoder::Opcode$< I_FLDLN2 >::Test(list, is64); break;
            case I_FLDPI:               encoder::Opcode$< I_FLDPI >::Test(list, is64); break;
            case I_FLDZ:                encoder::Opcode$< I_FLDZ >::Test(list, is64); break;
            case I_FMUL:                encoder::Opcode$< I_FMUL >::Test(list, is64); break;
            case I_FMULP:               encoder::Opcode$< I_FMULP >::Test(list, is64); break;
            case I_FNCLEX:              encoder::Opcode$< I_FNCLEX >::Test(list, is64); break;
            case I_FNINIT:              encoder::Opcode$< I_FNINIT >::Test(list, is64); break;
            case I_FNOP:                encoder::Opcode$< I_FNOP >::Test(list, is64); break;
            case I_FNSAVE:              encoder::Opcode$< I_FNSAVE >::Test(list, is64); break;
            case I_FNSTCW:              encoder::Opcode$< I_FNSTCW >::Test(list, is64); break;
            case I_FNSTENV:             encoder::Opcode$< I_FNSTENV >::Test(list, is64); break;
            case I_FNSTSW:              encoder::Opcode$< I_FNSTSW >::Test(list, is64); break;
            case I_FPATAN:              encoder::Opcode$< I_FPATAN >::Test(list, is64); break;
            case I_FPREM:               encoder::Opcode$< I_FPREM >::Test(list, is64); break;
            case I_FPREM1:              encoder::Opcode$< I_FPREM1 >::Test(list, is64); break;
            case I_FPTAN:               encoder::Opcode$< I_FPTAN >::Test(list, is64); break;
            case I_FRNDINT:             encoder::Opcode$< I_FRNDINT >::Test(list, is64); break;
            case I_FRSTOR:              encoder::Opcode$< I_FRSTOR >::Test(list, is64); break;
            case I_FSCALE:              encoder::Opcode$< I_FSCALE >::Test(list, is64); break;
            case I_FSETPM:              encoder::Opcode$< I_FSETPM >::Test(list, is64); break;
            case I_FSIN:                encoder::Opcode$< I_FSIN >::Test(list, is64); break;
            case I_FSINCOS:             encoder::Opcode$< I_FSINCOS >::Test(list, is64); break;
            case I_FSQRT:               encoder::Opcode$< I_FSQRT >::Test(list, is64); break;
            case I_FST:                 encoder::Opcode$< I_FST >::Test(list, is64); break;
            case I_FSTP:                encoder::Opcode$< I_FSTP >::Test(list, is64); break;
            case I_FSTPNCE:             encoder::Opcode$< I_FSTPNCE >::Test(list, is64); break;
            case I_FSUB:                encoder::Opcode$< I_FSUB >::Test(list, is64); break;
            case I_FSUBP:               encoder::Opcode$< I_FSUBP >::Test(list, is64); break;
            case I_FSUBR:               encoder::Opcode$< I_FSUBR >::Test(list, is64); break;
            case I_FSUBRP:              encoder::Opcode$< I_FSUBRP >::Test(list, is64); break;
            case I_FTST:                encoder::Opcode$< I_FTST >::Test(list, is64); break;
            case I_FUCOM:               encoder::Opcode$< I_FUCOM >::Test(list, is64); break;
            case I_FUCOMI:              encoder::Opcode$< I_FUCOMI >::Test(list, is64); break;
            case I_FUCOMP:              encoder::Opcode$< I_FUCOMP >::Test(list, is64); break;
            case I_FUCOMPI:             encoder::Opcode$< I_FUCOMPI >::Test(list, is64); break;
            case I_FUCOMPP:             encoder::Opcode$< I_FUCOMPP >::Test(list, is64); break;
            case I_FXAM:                encoder::Opcode$< I_FXAM >::Test(list, is64); break;
            case I_FXCH:                encoder::Opcode$< I_FXCH >::Test(list, is64); break;
            case I_FXRSTOR:             encoder::Opcode$< I_FXRSTOR >::Test(list, is64); break;
            case I_FXRSTOR64:           encoder::Opcode$< I_FXRSTOR64 >::Test(list, is64); break;
            case I_FXSAVE:              encoder::Opcode$< I_FXSAVE >::Test(list, is64); break;
            case I_FXSAVE64:            encoder::Opcode$< I_FXSAVE64 >::Test(list, is64); break;
            case I_FXTRACT:             encoder::Opcode$< I_FXTRACT >::Test(list, is64); break;
            case I_FYL2X:               encoder::Opcode$< I_FYL2X >::Test(list, is64); break;
            case I_FYL2XP1:             encoder::Opcode$< I_FYL2XP1 >::Test(list, is64); break;
            case I_GETSEC:              encoder::Opcode$< I_GETSEC >::Test(list, is64); break;
            case I_HADDPD:              encoder::Opcode$< I_HADDPD >::Test(list, is64); break;
            case I_HADDPS:              encoder::Opcode$< I_HADDPS >::Test(list, is64); break;
            case I_HLT:                 encoder::Opcode$< I_HLT >::Test(list, is64); break;
            case I_HSUBPD:              encoder::Opcode$< I_HSUBPD >::Test(list, is64); break;
            case I_HSUBPS:              encoder::Opcode$< I_HSUBPS >::Test(list, is64); break;
            case I_IDIV:                encoder::Opcode$< I_IDIV >::Test(list, is64); break;
            case I_IMUL:                encoder::Opcode$< I_IMUL >::Test(list, is64); break;
            case I_IN:                  encoder::Opcode$< I_IN >::Test(list, is64); break;
            case I_INC:                 encoder::Opcode$< I_INC >::Test(list, is64); break;
            case I_INS:                 encoder::Opcode$< I_INS >::Test(list, is64); break;
            case I_INSERTPS:            encoder::Opcode$< I_INSERTPS >::Test(list, is64); break;
            case I_INSERTQ:             encoder::Opcode$< I_INSERTQ >::Test(list, is64); break;
            case I_INT:                 encoder::Opcode$< I_INT >::Test(list, is64); break;
            case I_INT1:                encoder::Opcode$< I_INT1 >::Test(list, is64); break;
            case I_INT3:                encoder::Opcode$< I_INT3 >::Test(list, is64); break;
            case I_INTO:                encoder::Opcode$< I_INTO >::Test(list, is64); break;
            case I_INVD:                encoder::Opcode$< I_INVD >::Test(list, is64); break;
            case I_INVEPT:              encoder::Opcode$< I_INVEPT >::Test(list, is64); break;
            case I_INVLPG:              encoder::Opcode$< I_INVLPG >::Test(list, is64); break;
            case I_INVLPGA:             encoder::Opcode$< I_INVLPGA >::Test(list, is64); break;
            case I_INVPCID:             encoder::Opcode$< I_INVPCID >::Test(list, is64); break;
            case I_INVVPID:             encoder::Opcode$< I_INVVPID >::Test(list, is64); break;
            case I_IRET:                encoder::Opcode$< I_IRET >::Test(list, is64); break;
            case I_IRETD:               encoder::Opcode$< I_IRETD >::Test(list, is64); break;
            case I_IRETQ:               encoder::Opcode$< I_IRETQ >::Test(list, is64); break;
            case I_JCC:                 encoder::Opcode$< I_JCC >::Test(list, is64); break;
            case I_JMP:                 encoder::Opcode$< I_JMP >::Test(list, is64); break;
            case I_KANDB:               encoder::Opcode$< I_KANDB >::Test(list, is64); break;
            case I_KANDD:               encoder::Opcode$< I_KANDD >::Test(list, is64); break;
            case I_KANDNB:              encoder::Opcode$< I_KANDNB >::Test(list, is64); break;
            case I_KANDND:              encoder::Opcode$< I_KANDND >::Test(list, is64); break;
            case I_KANDNQ:              encoder::Opcode$< I_KANDNQ >::Test(list, is64); break;
            case I_KANDNW:              encoder::Opcode$< I_KANDNW >::Test(list, is64); break;
            case I_KANDQ:               encoder::Opcode$< I_KANDQ >::Test(list, is64); break;
            case I_KANDW:               encoder::Opcode$< I_KANDW >::Test(list, is64); break;
            case I_KMOVB:               encoder::Opcode$< I_KMOVB >::Test(list, is64); break;
            case I_KMOVD:               encoder::Opcode$< I_KMOVD >::Test(list, is64); break;
            case I_KMOVQ:               encoder::Opcode$< I_KMOVQ >::Test(list, is64); break;
            case I_KMOVW:               encoder::Opcode$< I_KMOVW >::Test(list, is64); break;
            case I_KNOTB:               encoder::Opcode$< I_KNOTB >::Test(list, is64); break;
            case I_KNOTD:               encoder::Opcode$< I_KNOTD >::Test(list, is64); break;
            case I_KNOTQ:               encoder::Opcode$< I_KNOTQ >::Test(list, is64); break;
            case I_KNOTW:               encoder::Opcode$< I_KNOTW >::Test(list, is64); break;
            case I_KORB:                encoder::Opcode$< I_KORB >::Test(list, is64); break;
            case I_KORD:                encoder::Opcode$< I_KORD >::Test(list, is64); break;
            case I_KORQ:                encoder::Opcode$< I_KORQ >::Test(list, is64); break;
            case I_KORTESTW:            encoder::Opcode$< I_KORTESTW >::Test(list, is64); break;
            case I_KORW:                encoder::Opcode$< I_KORW >::Test(list, is64); break;
            case I_KSHIFTLW:            encoder::Opcode$< I_KSHIFTLW >::Test(list, is64); break;
            case I_KSHIFTRW:            encoder::Opcode$< I_KSHIFTRW >::Test(list, is64); break;
            case I_KUNPCKBW:            encoder::Opcode$< I_KUNPCKBW >::Test(list, is64); break;
            case I_KXNORB:              encoder::Opcode$< I_KXNORB >::Test(list, is64); break;
            case I_KXNORD:              encoder::Opcode$< I_KXNORD >::Test(list, is64); break;
            case I_KXNORQ:              encoder::Opcode$< I_KXNORQ >::Test(list, is64); break;
            case I_KXNORW:              encoder::Opcode$< I_KXNORW >::Test(list, is64); break;
            case I_KXORB:               encoder::Opcode$< I_KXORB >::Test(list, is64); break;
            case I_KXORD:               encoder::Opcode$< I_KXORD >::Test(list, is64); break;
            case I_KXORQ:               encoder::Opcode$< I_KXORQ >::Test(list, is64); break;
            case I_KXORW:               encoder::Opcode$< I_KXORW >::Test(list, is64); break;
            case I_LAHF:                encoder::Opcode$< I_LAHF >::Test(list, is64); break;
            case I_LAR:                 encoder::Opcode$< I_LAR >::Test(list, is64); break;
            case I_LCALL:               encoder::Opcode$< I_LCALL >::Test(list, is64); break;
            case I_LDDQU:               encoder::Opcode$< I_LDDQU >::Test(list, is64); break;
            case I_LDMXCSR:             encoder::Opcode$< I_LDMXCSR >::Test(list, is64); break;
            case I_LDS:                 encoder::Opcode$< I_LDS >::Test(list, is64); break;
            case I_LEA:                 encoder::Opcode$< I_LEA >::Test(list, is64); break;
            case I_LEAVE:               encoder::Opcode$< I_LEAVE >::Test(list, is64); break;
            case I_LES:                 encoder::Opcode$< I_LES >::Test(list, is64); break;
            case I_LFENCE:              encoder::Opcode$< I_LFENCE >::Test(list, is64); break;
            case I_LFS:                 encoder::Opcode$< I_LFS >::Test(list, is64); break;
            case I_LGDT:                encoder::Opcode$< I_LGDT >::Test(list, is64); break;
            case I_LGS:                 encoder::Opcode$< I_LGS >::Test(list, is64); break;
            case I_LIDT:                encoder::Opcode$< I_LIDT >::Test(list, is64); break;
            case I_LJMP:                encoder::Opcode$< I_LJMP >::Test(list, is64); break;
            case I_LLDT:                encoder::Opcode$< I_LLDT >::Test(list, is64); break;
            case I_LMSW:                encoder::Opcode$< I_LMSW >::Test(list, is64); break;
            case I_LOCK:                encoder::Opcode$< I_LOCK >::Test(list, is64); break;
            case I_LODS:                encoder::Opcode$< I_LODS >::Test(list, is64); break;
            case I_LOOPCC:              encoder::Opcode$< I_LOOPCC >::Test(list, is64); break;
            case I_LSL:                 encoder::Opcode$< I_LSL >::Test(list, is64); break;
            case I_LSS:                 encoder::Opcode$< I_LSS >::Test(list, is64); break;
            case I_LTR:                 encoder::Opcode$< I_LTR >::Test(list, is64); break;
            case I_LZCNT:               encoder::Opcode$< I_LZCNT >::Test(list, is64); break;
            case I_MASKMOVDQU:          encoder::Opcode$< I_MASKMOVDQU >::Test(list, is64); break;
            case I_MASKMOVQ:            encoder::Opcode$< I_MASKMOVQ >::Test(list, is64); break;
            case I_MAXPD:               encoder::Opcode$< I_MAXPD >::Test(list, is64); break;
            case I_MAXPS:               encoder::Opcode$< I_MAXPS >::Test(list, is64); break;
            case I_MAXSD:               encoder::Opcode$< I_MAXSD >::Test(list, is64); break;
            case I_MAXSS:               encoder::Opcode$< I_MAXSS >::Test(list, is64); break;
            case I_MFENCE:              encoder::Opcode$< I_MFENCE >::Test(list, is64); break;
            case I_MINPD:               encoder::Opcode$< I_MINPD >::Test(list, is64); break;
            case I_MINPS:               encoder::Opcode$< I_MINPS >::Test(list, is64); break;
            case I_MINSD:               encoder::Opcode$< I_MINSD >::Test(list, is64); break;
            case I_MINSS:               encoder::Opcode$< I_MINSS >::Test(list, is64); break;
            case I_MONITOR:             encoder::Opcode$< I_MONITOR >::Test(list, is64); break;
            case I_MONTMUL:             encoder::Opcode$< I_MONTMUL >::Test(list, is64); break;
            case I_MOV:                 encoder::Opcode$< I_MOV >::Test(list, is64); break;
            case I_MOVABS:              encoder::Opcode$< I_MOVABS >::Test(list, is64); break;
            case I_MOVAPD:              encoder::Opcode$< I_MOVAPD >::Test(list, is64); break;
            case I_MOVAPS:              encoder::Opcode$< I_MOVAPS >::Test(list, is64); break;
            case I_MOVBE:               encoder::Opcode$< I_MOVBE >::Test(list, is64); break;
            case I_MOVD:                encoder::Opcode$< I_MOVD >::Test(list, is64); break;
            case I_MOVDDUP:             encoder::Opcode$< I_MOVDDUP >::Test(list, is64); break;
            case I_MOVDQ2Q:             encoder::Opcode$< I_MOVDQ2Q >::Test(list, is64); break;
            case I_MOVDQA:              encoder::Opcode$< I_MOVDQA >::Test(list, is64); break;
            case I_MOVDQU:              encoder::Opcode$< I_MOVDQU >::Test(list, is64); break;
            case I_MOVHLPS:             encoder::Opcode$< I_MOVHLPS >::Test(list, is64); break;
            case I_MOVHPD:              encoder::Opcode$< I_MOVHPD >::Test(list, is64); break;
            case I_MOVHPS:              encoder::Opcode$< I_MOVHPS >::Test(list, is64); break;
            case I_MOVLHPS:             encoder::Opcode$< I_MOVLHPS >::Test(list, is64); break;
            case I_MOVLPD:              encoder::Opcode$< I_MOVLPD >::Test(list, is64); break;
            case I_MOVLPS:              encoder::Opcode$< I_MOVLPS >::Test(list, is64); break;
            case I_MOVMSKPD:            encoder::Opcode$< I_MOVMSKPD >::Test(list, is64); break;
            case I_MOVMSKPS:            encoder::Opcode$< I_MOVMSKPS >::Test(list, is64); break;
            case I_MOVNTDQ:             encoder::Opcode$< I_MOVNTDQ >::Test(list, is64); break;
            case I_MOVNTDQA:            encoder::Opcode$< I_MOVNTDQA >::Test(list, is64); break;
            case I_MOVNTI:              encoder::Opcode$< I_MOVNTI >::Test(list, is64); break;
            case I_MOVNTPD:             encoder::Opcode$< I_MOVNTPD >::Test(list, is64); break;
            case I_MOVNTPS:             encoder::Opcode$< I_MOVNTPS >::Test(list, is64); break;
            case I_MOVNTQ:              encoder::Opcode$< I_MOVNTQ >::Test(list, is64); break;
            case I_MOVNTSD:             encoder::Opcode$< I_MOVNTSD >::Test(list, is64); break;
            case I_MOVNTSS:             encoder::Opcode$< I_MOVNTSS >::Test(list, is64); break;
            case I_MOVQ:                encoder::Opcode$< I_MOVQ >::Test(list, is64); break;
            case I_MOVQ2DQ:             encoder::Opcode$< I_MOVQ2DQ >::Test(list, is64); break;
            case I_MOVS:                encoder::Opcode$< I_MOVS >::Test(list, is64); break;
            case I_MOVSD:               encoder::Opcode$< I_MOVSD >::Test(list, is64); break;
            case I_MOVSHDUP:            encoder::Opcode$< I_MOVSHDUP >::Test(list, is64); break;
            case I_MOVSLDUP:            encoder::Opcode$< I_MOVSLDUP >::Test(list, is64); break;
            case I_MOVSS:               encoder::Opcode$< I_MOVSS >::Test(list, is64); break;
            case I_MOVSX:               encoder::Opcode$< I_MOVSX >::Test(list, is64); break;
            case I_MOVSXD:              encoder::Opcode$< I_MOVSXD >::Test(list, is64); break;
            case I_MOVUPD:              encoder::Opcode$< I_MOVUPD >::Test(list, is64); break;
            case I_MOVUPS:              encoder::Opcode$< I_MOVUPS >::Test(list, is64); break;
            case I_MOVZX:               encoder::Opcode$< I_MOVZX >::Test(list, is64); break;
            case I_MPSADBW:             encoder::Opcode$< I_MPSADBW >::Test(list, is64); break;
            case I_MUL:                 encoder::Opcode$< I_MUL >::Test(list, is64); break;
            case I_MULPD:               encoder::Opcode$< I_MULPD >::Test(list, is64); break;
            case I_MULPS:               encoder::Opcode$< I_MULPS >::Test(list, is64); break;
            case I_MULSD:               encoder::Opcode$< I_MULSD >::Test(list, is64); break;
            case I_MULSS:               encoder::Opcode$< I_MULSS >::Test(list, is64); break;
            case I_MULX:                encoder::Opcode$< I_MULX >::Test(list, is64); break;
            case I_MWAIT:               encoder::Opcode$< I_MWAIT >::Test(list, is64); break;
            case I_NEG:                 encoder::Opcode$< I_NEG >::Test(list, is64); break;
            case I_NOP:                 encoder::Opcode$< I_NOP >::Test(list, is64); break;
            case I_NOT:                 encoder::Opcode$< I_NOT >::Test(list, is64); break;
            case I_OR:                  encoder::Opcode$< I_OR >::Test(list, is64); break;
            case I_ORPD:                encoder::Opcode$< I_ORPD >::Test(list, is64); break;
            case I_ORPS:                encoder::Opcode$< I_ORPS >::Test(list, is64); break;
            case I_OUT:                 encoder::Opcode$< I_OUT >::Test(list, is64); break;
            case I_OUTS:                encoder::Opcode$< I_OUTS >::Test(list, is64); break;
            case I_PABSB:               encoder::Opcode$< I_PABSB >::Test(list, is64); break;
            case I_PABSD:               encoder::Opcode$< I_PABSD >::Test(list, is64); break;
            case I_PABSW:               encoder::Opcode$< I_PABSW >::Test(list, is64); break;
            case I_PACKSSDW:            encoder::Opcode$< I_PACKSSDW >::Test(list, is64); break;
            case I_PACKSSWB:            encoder::Opcode$< I_PACKSSWB >::Test(list, is64); break;
            case I_PACKUSDW:            encoder::Opcode$< I_PACKUSDW >::Test(list, is64); break;
            case I_PACKUSWB:            encoder::Opcode$< I_PACKUSWB >::Test(list, is64); break;
            case I_PADDB:               encoder::Opcode$< I_PADDB >::Test(list, is64); break;
            case I_PADDD:               encoder::Opcode$< I_PADDD >::Test(list, is64); break;
            case I_PADDQ:               encoder::Opcode$< I_PADDQ >::Test(list, is64); break;
            case I_PADDSB:              encoder::Opcode$< I_PADDSB >::Test(list, is64); break;
            case I_PADDSW:              encoder::Opcode$< I_PADDSW >::Test(list, is64); break;
            case I_PADDUSB:             encoder::Opcode$< I_PADDUSB >::Test(list, is64); break;
            case I_PADDUSW:             encoder::Opcode$< I_PADDUSW >::Test(list, is64); break;
            case I_PADDW:               encoder::Opcode$< I_PADDW >::Test(list, is64); break;
            case I_PALIGNR:             encoder::Opcode$< I_PALIGNR >::Test(list, is64); break;
            case I_PAND:                encoder::Opcode$< I_PAND >::Test(list, is64); break;
            case I_PANDN:               encoder::Opcode$< I_PANDN >::Test(list, is64); break;
            case I_PAUSE:               encoder::Opcode$< I_PAUSE >::Test(list, is64); break;
            case I_PAVGB:               encoder::Opcode$< I_PAVGB >::Test(list, is64); break;
            case I_PAVGUSB:             encoder::Opcode$< I_PAVGUSB >::Test(list, is64); break;
            case I_PAVGW:               encoder::Opcode$< I_PAVGW >::Test(list, is64); break;
            case I_PBLENDVB:            encoder::Opcode$< I_PBLENDVB >::Test(list, is64); break;
            case I_PBLENDW:             encoder::Opcode$< I_PBLENDW >::Test(list, is64); break;
            case I_PCLMULQDQ:           encoder::Opcode$< I_PCLMULQDQ >::Test(list, is64); break;
            case I_PCMPEQB:             encoder::Opcode$< I_PCMPEQB >::Test(list, is64); break;
            case I_PCMPEQD:             encoder::Opcode$< I_PCMPEQD >::Test(list, is64); break;
            case I_PCMPEQQ:             encoder::Opcode$< I_PCMPEQQ >::Test(list, is64); break;
            case I_PCMPEQW:             encoder::Opcode$< I_PCMPEQW >::Test(list, is64); break;
            case I_PCMPESTRI:           encoder::Opcode$< I_PCMPESTRI >::Test(list, is64); break;
            case I_PCMPESTRM:           encoder::Opcode$< I_PCMPESTRM >::Test(list, is64); break;
            case I_PCMPGTB:             encoder::Opcode$< I_PCMPGTB >::Test(list, is64); break;
            case I_PCMPGTD:             encoder::Opcode$< I_PCMPGTD >::Test(list, is64); break;
            case I_PCMPGTQ:             encoder::Opcode$< I_PCMPGTQ >::Test(list, is64); break;
            case I_PCMPGTW:             encoder::Opcode$< I_PCMPGTW >::Test(list, is64); break;
            case I_PCMPISTRI:           encoder::Opcode$< I_PCMPISTRI >::Test(list, is64); break;
            case I_PCMPISTRM:           encoder::Opcode$< I_PCMPISTRM >::Test(list, is64); break;
            case I_PDEP:                encoder::Opcode$< I_PDEP >::Test(list, is64); break;
            case I_PEXT:                encoder::Opcode$< I_PEXT >::Test(list, is64); break;
            case I_PEXTRB:              encoder::Opcode$< I_PEXTRB >::Test(list, is64); break;
            case I_PEXTRD:              encoder::Opcode$< I_PEXTRD >::Test(list, is64); break;
            case I_PEXTRQ:              encoder::Opcode$< I_PEXTRQ >::Test(list, is64); break;
            case I_PEXTRW:              encoder::Opcode$< I_PEXTRW >::Test(list, is64); break;
            case I_PF2ID:               encoder::Opcode$< I_PF2ID >::Test(list, is64); break;
            case I_PF2IW:               encoder::Opcode$< I_PF2IW >::Test(list, is64); break;
            case I_PFACC:               encoder::Opcode$< I_PFACC >::Test(list, is64); break;
            case I_PFADD:               encoder::Opcode$< I_PFADD >::Test(list, is64); break;
            case I_PFCMPEQ:             encoder::Opcode$< I_PFCMPEQ >::Test(list, is64); break;
            case I_PFCMPGE:             encoder::Opcode$< I_PFCMPGE >::Test(list, is64); break;
            case I_PFCMPGT:             encoder::Opcode$< I_PFCMPGT >::Test(list, is64); break;
            case I_PFMAX:               encoder::Opcode$< I_PFMAX >::Test(list, is64); break;
            case I_PFMIN:               encoder::Opcode$< I_PFMIN >::Test(list, is64); break;
            case I_PFMUL:               encoder::Opcode$< I_PFMUL >::Test(list, is64); break;
            case I_PFNACC:              encoder::Opcode$< I_PFNACC >::Test(list, is64); break;
            case I_PFPNACC:             encoder::Opcode$< I_PFPNACC >::Test(list, is64); break;
            case I_PFRCP:               encoder::Opcode$< I_PFRCP >::Test(list, is64); break;
            case I_PFRCPIT1:            encoder::Opcode$< I_PFRCPIT1 >::Test(list, is64); break;
            case I_PFRCPIT2:            encoder::Opcode$< I_PFRCPIT2 >::Test(list, is64); break;
            case I_PFRSQIT1:            encoder::Opcode$< I_PFRSQIT1 >::Test(list, is64); break;
            case I_PFRSQRT:             encoder::Opcode$< I_PFRSQRT >::Test(list, is64); break;
            case I_PFSUB:               encoder::Opcode$< I_PFSUB >::Test(list, is64); break;
            case I_PFSUBR:              encoder::Opcode$< I_PFSUBR >::Test(list, is64); break;
            case I_PHADDD:              encoder::Opcode$< I_PHADDD >::Test(list, is64); break;
            case I_PHADDSW:             encoder::Opcode$< I_PHADDSW >::Test(list, is64); break;
            case I_PHADDW:              encoder::Opcode$< I_PHADDW >::Test(list, is64); break;
            case I_PHMINPOSUW:          encoder::Opcode$< I_PHMINPOSUW >::Test(list, is64); break;
            case I_PHSUBD:              encoder::Opcode$< I_PHSUBD >::Test(list, is64); break;
            case I_PHSUBSW:             encoder::Opcode$< I_PHSUBSW >::Test(list, is64); break;
            case I_PHSUBW:              encoder::Opcode$< I_PHSUBW >::Test(list, is64); break;
            case I_PI2FD:               encoder::Opcode$< I_PI2FD >::Test(list, is64); break;
            case I_PI2FW:               encoder::Opcode$< I_PI2FW >::Test(list, is64); break;
            case I_PINSRB:              encoder::Opcode$< I_PINSRB >::Test(list, is64); break;
            case I_PINSRD:              encoder::Opcode$< I_PINSRD >::Test(list, is64); break;
            case I_PINSRQ:              encoder::Opcode$< I_PINSRQ >::Test(list, is64); break;
            case I_PINSRW:              encoder::Opcode$< I_PINSRW >::Test(list, is64); break;
            case I_PMADDUBSW:           encoder::Opcode$< I_PMADDUBSW >::Test(list, is64); break;
            case I_PMADDWD:             encoder::Opcode$< I_PMADDWD >::Test(list, is64); break;
            case I_PMAXSB:              encoder::Opcode$< I_PMAXSB >::Test(list, is64); break;
            case I_PMAXSD:              encoder::Opcode$< I_PMAXSD >::Test(list, is64); break;
            case I_PMAXSW:              encoder::Opcode$< I_PMAXSW >::Test(list, is64); break;
            case I_PMAXUB:              encoder::Opcode$< I_PMAXUB >::Test(list, is64); break;
            case I_PMAXUD:              encoder::Opcode$< I_PMAXUD >::Test(list, is64); break;
            case I_PMAXUW:              encoder::Opcode$< I_PMAXUW >::Test(list, is64); break;
            case I_PMINSB:              encoder::Opcode$< I_PMINSB >::Test(list, is64); break;
            case I_PMINSD:              encoder::Opcode$< I_PMINSD >::Test(list, is64); break;
            case I_PMINSW:              encoder::Opcode$< I_PMINSW >::Test(list, is64); break;
            case I_PMINUB:              encoder::Opcode$< I_PMINUB >::Test(list, is64); break;
            case I_PMINUD:              encoder::Opcode$< I_PMINUD >::Test(list, is64); break;
            case I_PMINUW:              encoder::Opcode$< I_PMINUW >::Test(list, is64); break;
            case I_PMOVMSKB:            encoder::Opcode$< I_PMOVMSKB >::Test(list, is64); break;
            case I_PMOVSXBD:            encoder::Opcode$< I_PMOVSXBD >::Test(list, is64); break;
            case I_PMOVSXBQ:            encoder::Opcode$< I_PMOVSXBQ >::Test(list, is64); break;
            case I_PMOVSXBW:            encoder::Opcode$< I_PMOVSXBW >::Test(list, is64); break;
            case I_PMOVSXDQ:            encoder::Opcode$< I_PMOVSXDQ >::Test(list, is64); break;
            case I_PMOVSXWD:            encoder::Opcode$< I_PMOVSXWD >::Test(list, is64); break;
            case I_PMOVSXWQ:            encoder::Opcode$< I_PMOVSXWQ >::Test(list, is64); break;
            case I_PMOVZXBD:            encoder::Opcode$< I_PMOVZXBD >::Test(list, is64); break;
            case I_PMOVZXBQ:            encoder::Opcode$< I_PMOVZXBQ >::Test(list, is64); break;
            case I_PMOVZXBW:            encoder::Opcode$< I_PMOVZXBW >::Test(list, is64); break;
            case I_PMOVZXDQ:            encoder::Opcode$< I_PMOVZXDQ >::Test(list, is64); break;
            case I_PMOVZXWD:            encoder::Opcode$< I_PMOVZXWD >::Test(list, is64); break;
            case I_PMOVZXWQ:            encoder::Opcode$< I_PMOVZXWQ >::Test(list, is64); break;
            case I_PMULDQ:              encoder::Opcode$< I_PMULDQ >::Test(list, is64); break;
            case I_PMULHRSW:            encoder::Opcode$< I_PMULHRSW >::Test(list, is64); break;
            case I_PMULHRW:             encoder::Opcode$< I_PMULHRW >::Test(list, is64); break;
            case I_PMULHUW:             encoder::Opcode$< I_PMULHUW >::Test(list, is64); break;
            case I_PMULHW:              encoder::Opcode$< I_PMULHW >::Test(list, is64); break;
            case I_PMULLD:              encoder::Opcode$< I_PMULLD >::Test(list, is64); break;
            case I_PMULLW:              encoder::Opcode$< I_PMULLW >::Test(list, is64); break;
            case I_PMULUDQ:             encoder::Opcode$< I_PMULUDQ >::Test(list, is64); break;
            case I_POP:                 encoder::Opcode$< I_POP >::Test(list, is64); break;
            case I_POPAL:               encoder::Opcode$< I_POPAL >::Test(list, is64); break;
            case I_POPAW:               encoder::Opcode$< I_POPAW >::Test(list, is64); break;
            case I_POPCNT:              encoder::Opcode$< I_POPCNT >::Test(list, is64); break;
            case I_POPF:                encoder::Opcode$< I_POPF >::Test(list, is64); break;
            case I_POPFD:               encoder::Opcode$< I_POPFD >::Test(list, is64); break;
            case I_POPFQ:               encoder::Opcode$< I_POPFQ >::Test(list, is64); break;
            case I_POR:                 encoder::Opcode$< I_POR >::Test(list, is64); break;
            case I_PREFETCH:            encoder::Opcode$< I_PREFETCH >::Test(list, is64); break;
            case I_PREFETCHNTA:         encoder::Opcode$< I_PREFETCHNTA >::Test(list, is64); break;
            case I_PREFETCHT0:          encoder::Opcode$< I_PREFETCHT0 >::Test(list, is64); break;
            case I_PREFETCHT1:          encoder::Opcode$< I_PREFETCHT1 >::Test(list, is64); break;
            case I_PREFETCHT2:          encoder::Opcode$< I_PREFETCHT2 >::Test(list, is64); break;
            case I_PREFETCHW:           encoder::Opcode$< I_PREFETCHW >::Test(list, is64); break;
            case I_PSADBW:              encoder::Opcode$< I_PSADBW >::Test(list, is64); break;
            case I_PSHUFB:              encoder::Opcode$< I_PSHUFB >::Test(list, is64); break;
            case I_PSHUFD:              encoder::Opcode$< I_PSHUFD >::Test(list, is64); break;
            case I_PSHUFHW:             encoder::Opcode$< I_PSHUFHW >::Test(list, is64); break;
            case I_PSHUFLW:             encoder::Opcode$< I_PSHUFLW >::Test(list, is64); break;
            case I_PSHUFW:              encoder::Opcode$< I_PSHUFW >::Test(list, is64); break;
            case I_PSIGNB:              encoder::Opcode$< I_PSIGNB >::Test(list, is64); break;
            case I_PSIGND:              encoder::Opcode$< I_PSIGND >::Test(list, is64); break;
            case I_PSIGNW:              encoder::Opcode$< I_PSIGNW >::Test(list, is64); break;
            case I_PSLLD:               encoder::Opcode$< I_PSLLD >::Test(list, is64); break;
            case I_PSLLDQ:              encoder::Opcode$< I_PSLLDQ >::Test(list, is64); break;
            case I_PSLLQ:               encoder::Opcode$< I_PSLLQ >::Test(list, is64); break;
            case I_PSLLW:               encoder::Opcode$< I_PSLLW >::Test(list, is64); break;
            case I_PSRAD:               encoder::Opcode$< I_PSRAD >::Test(list, is64); break;
            case I_PSRAW:               encoder::Opcode$< I_PSRAW >::Test(list, is64); break;
            case I_PSRLD:               encoder::Opcode$< I_PSRLD >::Test(list, is64); break;
            case I_PSRLDQ:              encoder::Opcode$< I_PSRLDQ >::Test(list, is64); break;
            case I_PSRLQ:               encoder::Opcode$< I_PSRLQ >::Test(list, is64); break;
            case I_PSRLW:               encoder::Opcode$< I_PSRLW >::Test(list, is64); break;
            case I_PSUBB:               encoder::Opcode$< I_PSUBB >::Test(list, is64); break;
            case I_PSUBD:               encoder::Opcode$< I_PSUBD >::Test(list, is64); break;
            case I_PSUBQ:               encoder::Opcode$< I_PSUBQ >::Test(list, is64); break;
            case I_PSUBSB:              encoder::Opcode$< I_PSUBSB >::Test(list, is64); break;
            case I_PSUBSW:              encoder::Opcode$< I_PSUBSW >::Test(list, is64); break;
            case I_PSUBUSB:             encoder::Opcode$< I_PSUBUSB >::Test(list, is64); break;
            case I_PSUBUSW:             encoder::Opcode$< I_PSUBUSW >::Test(list, is64); break;
            case I_PSUBW:               encoder::Opcode$< I_PSUBW >::Test(list, is64); break;
            case I_PSWAPD:              encoder::Opcode$< I_PSWAPD >::Test(list, is64); break;
            case I_PTEST:               encoder::Opcode$< I_PTEST >::Test(list, is64); break;
            case I_PUNPCKHBW:           encoder::Opcode$< I_PUNPCKHBW >::Test(list, is64); break;
            case I_PUNPCKHDQ:           encoder::Opcode$< I_PUNPCKHDQ >::Test(list, is64); break;
            case I_PUNPCKHQDQ:          encoder::Opcode$< I_PUNPCKHQDQ >::Test(list, is64); break;
            case I_PUNPCKHWD:           encoder::Opcode$< I_PUNPCKHWD >::Test(list, is64); break;
            case I_PUNPCKLBW:           encoder::Opcode$< I_PUNPCKLBW >::Test(list, is64); break;
            case I_PUNPCKLDQ:           encoder::Opcode$< I_PUNPCKLDQ >::Test(list, is64); break;
            case I_PUNPCKLQDQ:          encoder::Opcode$< I_PUNPCKLQDQ >::Test(list, is64); break;
            case I_PUNPCKLWD:           encoder::Opcode$< I_PUNPCKLWD >::Test(list, is64); break;
            case I_PUSH:                encoder::Opcode$< I_PUSH >::Test(list, is64); break;
            case I_PUSHAL:              encoder::Opcode$< I_PUSHAL >::Test(list, is64); break;
            case I_PUSHAW:              encoder::Opcode$< I_PUSHAW >::Test(list, is64); break;
            case I_PUSHF:               encoder::Opcode$< I_PUSHF >::Test(list, is64); break;
            case I_PUSHFD:              encoder::Opcode$< I_PUSHFD >::Test(list, is64); break;
            case I_PUSHFQ:              encoder::Opcode$< I_PUSHFQ >::Test(list, is64); break;
            case I_PXOR:                encoder::Opcode$< I_PXOR >::Test(list, is64); break;
            case I_RCL:                 encoder::Opcode$< I_RCL >::Test(list, is64); break;
            case I_RCPPS:               encoder::Opcode$< I_RCPPS >::Test(list, is64); break;
            case I_RCPSS:               encoder::Opcode$< I_RCPSS >::Test(list, is64); break;
            case I_RCR:                 encoder::Opcode$< I_RCR >::Test(list, is64); break;
            case I_RDFSBASE:            encoder::Opcode$< I_RDFSBASE >::Test(list, is64); break;
            case I_RDGSBASE:            encoder::Opcode$< I_RDGSBASE >::Test(list, is64); break;
            case I_RDMSR:               encoder::Opcode$< I_RDMSR >::Test(list, is64); break;
            case I_RDPMC:               encoder::Opcode$< I_RDPMC >::Test(list, is64); break;
            case I_RDRAND:              encoder::Opcode$< I_RDRAND >::Test(list, is64); break;
            case I_RDSEED:              encoder::Opcode$< I_RDSEED >::Test(list, is64); break;
            case I_RDTSC:               encoder::Opcode$< I_RDTSC >::Test(list, is64); break;
            case I_RDTSCP:              encoder::Opcode$< I_RDTSCP >::Test(list, is64); break;
            case I_REP:                 encoder::Opcode$< I_REP >::Test(list, is64); break;
            case I_REPNE:               encoder::Opcode$< I_REPNE >::Test(list, is64); break;
            case I_RET:                 encoder::Opcode$< I_RET >::Test(list, is64); break;
            case I_RETF:                encoder::Opcode$< I_RETF >::Test(list, is64); break;
            case I_RETFQ:               encoder::Opcode$< I_RETFQ >::Test(list, is64); break;
            case I_ROL:                 encoder::Opcode$< I_ROL >::Test(list, is64); break;
            case I_ROR:                 encoder::Opcode$< I_ROR >::Test(list, is64); break;
            case I_RORX:                encoder::Opcode$< I_RORX >::Test(list, is64); break;
            case I_ROUNDPD:             encoder::Opcode$< I_ROUNDPD >::Test(list, is64); break;
            case I_ROUNDPS:             encoder::Opcode$< I_ROUNDPS >::Test(list, is64); break;
            case I_ROUNDSD:             encoder::Opcode$< I_ROUNDSD >::Test(list, is64); break;
            case I_ROUNDSS:             encoder::Opcode$< I_ROUNDSS >::Test(list, is64); break;
            case I_RSM:                 encoder::Opcode$< I_RSM >::Test(list, is64); break;
            case I_RSQRTPS:             encoder::Opcode$< I_RSQRTPS >::Test(list, is64); break;
            case I_RSQRTSS:             encoder::Opcode$< I_RSQRTSS >::Test(list, is64); break;
            case I_SAHF:                encoder::Opcode$< I_SAHF >::Test(list, is64); break;
            case I_SAL:                 encoder::Opcode$< I_SAL >::Test(list, is64); break;
            case I_SALC:                encoder::Opcode$< I_SALC >::Test(list, is64); break;
            case I_SAR:                 encoder::Opcode$< I_SAR >::Test(list, is64); break;
            case I_SARX:                encoder::Opcode$< I_SARX >::Test(list, is64); break;
            case I_SBB:                 encoder::Opcode$< I_SBB >::Test(list, is64); break;
            case I_SCAS:                encoder::Opcode$< I_SCAS >::Test(list, is64); break;
            case I_SETcc:               encoder::Opcode$< I_SETcc >::Test(list, is64); break;
            case I_SFENCE:              encoder::Opcode$< I_SFENCE >::Test(list, is64); break;
            case I_SGDT:                encoder::Opcode$< I_SGDT >::Test(list, is64); break;
            case I_SHA1MSG1:            encoder::Opcode$< I_SHA1MSG1 >::Test(list, is64); break;
            case I_SHA1MSG2:            encoder::Opcode$< I_SHA1MSG2 >::Test(list, is64); break;
            case I_SHA1NEXTE:           encoder::Opcode$< I_SHA1NEXTE >::Test(list, is64); break;
            case I_SHA1RNDS4:           encoder::Opcode$< I_SHA1RNDS4 >::Test(list, is64); break;
            case I_SHA256MSG1:          encoder::Opcode$< I_SHA256MSG1 >::Test(list, is64); break;
            case I_SHA256MSG2:          encoder::Opcode$< I_SHA256MSG2 >::Test(list, is64); break;
            case I_SHA256RNDS2:         encoder::Opcode$< I_SHA256RNDS2 >::Test(list, is64); break;
            case I_SHL:                 encoder::Opcode$< I_SHL >::Test(list, is64); break;
            case I_SHLD:                encoder::Opcode$< I_SHLD >::Test(list, is64); break;
            case I_SHLX:                encoder::Opcode$< I_SHLX >::Test(list, is64); break;
            case I_SHR:                 encoder::Opcode$< I_SHR >::Test(list, is64); break;
            case I_SHRD:                encoder::Opcode$< I_SHRD >::Test(list, is64); break;
            case I_SHRX:                encoder::Opcode$< I_SHRX >::Test(list, is64); break;
            case I_SHUFPD:              encoder::Opcode$< I_SHUFPD >::Test(list, is64); break;
            case I_SHUFPS:              encoder::Opcode$< I_SHUFPS >::Test(list, is64); break;
            case I_SIDT:                encoder::Opcode$< I_SIDT >::Test(list, is64); break;
            case I_SKINIT:              encoder::Opcode$< I_SKINIT >::Test(list, is64); break;
            case I_SLDT:                encoder::Opcode$< I_SLDT >::Test(list, is64); break;
            case I_SMSW:                encoder::Opcode$< I_SMSW >::Test(list, is64); break;
            case I_SQRTPD:              encoder::Opcode$< I_SQRTPD >::Test(list, is64); break;
            case I_SQRTPS:              encoder::Opcode$< I_SQRTPS >::Test(list, is64); break;
            case I_SQRTSD:              encoder::Opcode$< I_SQRTSD >::Test(list, is64); break;
            case I_SQRTSS:              encoder::Opcode$< I_SQRTSS >::Test(list, is64); break;
            case I_STAC:                encoder::Opcode$< I_STAC >::Test(list, is64); break;
            case I_STC:                 encoder::Opcode$< I_STC >::Test(list, is64); break;
            case I_STD:                 encoder::Opcode$< I_STD >::Test(list, is64); break;
            case I_STGI:                encoder::Opcode$< I_STGI >::Test(list, is64); break;
            case I_STI:                 encoder::Opcode$< I_STI >::Test(list, is64); break;
            case I_STMXCSR:             encoder::Opcode$< I_STMXCSR >::Test(list, is64); break;
            case I_STOS:                encoder::Opcode$< I_STOS >::Test(list, is64); break;
            case I_STR:                 encoder::Opcode$< I_STR >::Test(list, is64); break;
            case I_SUB:                 encoder::Opcode$< I_SUB >::Test(list, is64); break;
            case I_SUBPD:               encoder::Opcode$< I_SUBPD >::Test(list, is64); break;
            case I_SUBPS:               encoder::Opcode$< I_SUBPS >::Test(list, is64); break;
            case I_SUBSD:               encoder::Opcode$< I_SUBSD >::Test(list, is64); break;
            case I_SUBSS:               encoder::Opcode$< I_SUBSS >::Test(list, is64); break;
            case I_SWAPGS:              encoder::Opcode$< I_SWAPGS >::Test(list, is64); break;
            case I_SYSCALL:             encoder::Opcode$< I_SYSCALL >::Test(list, is64); break;
            case I_SYSENTER:            encoder::Opcode$< I_SYSENTER >::Test(list, is64); break;
            case I_SYSEXIT:             encoder::Opcode$< I_SYSEXIT >::Test(list, is64); break;
            case I_SYSRET:              encoder::Opcode$< I_SYSRET >::Test(list, is64); break;
            case I_T1MSKC:              encoder::Opcode$< I_T1MSKC >::Test(list, is64); break;
            case I_TEST:                encoder::Opcode$< I_TEST >::Test(list, is64); break;
            case I_TZCNT:               encoder::Opcode$< I_TZCNT >::Test(list, is64); break;
            case I_TZMSK:               encoder::Opcode$< I_TZMSK >::Test(list, is64); break;
            case I_UCOMISD:             encoder::Opcode$< I_UCOMISD >::Test(list, is64); break;
            case I_UCOMISS:             encoder::Opcode$< I_UCOMISS >::Test(list, is64); break;
            case I_UD2:                 encoder::Opcode$< I_UD2 >::Test(list, is64); break;
            case I_UD2B:                encoder::Opcode$< I_UD2B >::Test(list, is64); break;
            case I_UNPCKHPD:            encoder::Opcode$< I_UNPCKHPD >::Test(list, is64); break;
            case I_UNPCKHPS:            encoder::Opcode$< I_UNPCKHPS >::Test(list, is64); break;
            case I_UNPCKLPD:            encoder::Opcode$< I_UNPCKLPD >::Test(list, is64); break;
            case I_UNPCKLPS:            encoder::Opcode$< I_UNPCKLPS >::Test(list, is64); break;
            case I_VADDPD:              encoder::Opcode$< I_VADDPD >::Test(list, is64); break;
            case I_VADDPS:              encoder::Opcode$< I_VADDPS >::Test(list, is64); break;
            case I_VADDSD:              encoder::Opcode$< I_VADDSD >::Test(list, is64); break;
            case I_VADDSS:              encoder::Opcode$< I_VADDSS >::Test(list, is64); break;
            case I_VADDSUBPD:           encoder::Opcode$< I_VADDSUBPD >::Test(list, is64); break;
            case I_VADDSUBPS:           encoder::Opcode$< I_VADDSUBPS >::Test(list, is64); break;
            case I_VAESDEC:             encoder::Opcode$< I_VAESDEC >::Test(list, is64); break;
            case I_VAESDECLAST:         encoder::Opcode$< I_VAESDECLAST >::Test(list, is64); break;
            case I_VAESENC:             encoder::Opcode$< I_VAESENC >::Test(list, is64); break;
            case I_VAESENCLAST:         encoder::Opcode$< I_VAESENCLAST >::Test(list, is64); break;
            case I_VAESIMC:             encoder::Opcode$< I_VAESIMC >::Test(list, is64); break;
            case I_VAESKEYGENASSIST:    encoder::Opcode$< I_VAESKEYGENASSIST >::Test(list, is64); break;
            case I_VALIGND:             encoder::Opcode$< I_VALIGND >::Test(list, is64); break;
            case I_VALIGNQ:             encoder::Opcode$< I_VALIGNQ >::Test(list, is64); break;
            case I_VANDNPD:             encoder::Opcode$< I_VANDNPD >::Test(list, is64); break;
            case I_VANDNPS:             encoder::Opcode$< I_VANDNPS >::Test(list, is64); break;
            case I_VANDPD:              encoder::Opcode$< I_VANDPD >::Test(list, is64); break;
            case I_VANDPS:              encoder::Opcode$< I_VANDPS >::Test(list, is64); break;
            case I_VBLENDMPD:           encoder::Opcode$< I_VBLENDMPD >::Test(list, is64); break;
            case I_VBLENDMPS:           encoder::Opcode$< I_VBLENDMPS >::Test(list, is64); break;
            case I_VBLENDPD:            encoder::Opcode$< I_VBLENDPD >::Test(list, is64); break;
            case I_VBLENDPS:            encoder::Opcode$< I_VBLENDPS >::Test(list, is64); break;
            case I_VBLENDVPD:           encoder::Opcode$< I_VBLENDVPD >::Test(list, is64); break;
            case I_VBLENDVPS:           encoder::Opcode$< I_VBLENDVPS >::Test(list, is64); break;
            case I_VBROADCASTF128:      encoder::Opcode$< I_VBROADCASTF128 >::Test(list, is64); break;
            case I_VBROADCASTI128:      encoder::Opcode$< I_VBROADCASTI128 >::Test(list, is64); break;
            case I_VBROADCASTI32X4:     encoder::Opcode$< I_VBROADCASTI32X4 >::Test(list, is64); break;
            case I_VBROADCASTI64X4:     encoder::Opcode$< I_VBROADCASTI64X4 >::Test(list, is64); break;
            case I_VBROADCASTSD:        encoder::Opcode$< I_VBROADCASTSD >::Test(list, is64); break;
            case I_VBROADCASTSS:        encoder::Opcode$< I_VBROADCASTSS >::Test(list, is64); break;
            case I_VCMP:                encoder::Opcode$< I_VCMP >::Test(list, is64); break;
            case I_VCMPPD:              encoder::Opcode$< I_VCMPPD >::Test(list, is64); break;
            case I_VCMPPS:              encoder::Opcode$< I_VCMPPS >::Test(list, is64); break;
            case I_VCMPSD:              encoder::Opcode$< I_VCMPSD >::Test(list, is64); break;
            case I_VCMPSS:              encoder::Opcode$< I_VCMPSS >::Test(list, is64); break;
            case I_VCOMISD:             encoder::Opcode$< I_VCOMISD >::Test(list, is64); break;
            case I_VCOMISS:             encoder::Opcode$< I_VCOMISS >::Test(list, is64); break;
            case I_VCVTDQ2PD:           encoder::Opcode$< I_VCVTDQ2PD >::Test(list, is64); break;
            case I_VCVTDQ2PS:           encoder::Opcode$< I_VCVTDQ2PS >::Test(list, is64); break;
            case I_VCVTPD2DQ:           encoder::Opcode$< I_VCVTPD2DQ >::Test(list, is64); break;
            case I_VCVTPD2DQX:          encoder::Opcode$< I_VCVTPD2DQX >::Test(list, is64); break;
            case I_VCVTPD2PS:           encoder::Opcode$< I_VCVTPD2PS >::Test(list, is64); break;
            case I_VCVTPD2PSX:          encoder::Opcode$< I_VCVTPD2PSX >::Test(list, is64); break;
            case I_VCVTPD2UDQ:          encoder::Opcode$< I_VCVTPD2UDQ >::Test(list, is64); break;
            case I_VCVTPH2PS:           encoder::Opcode$< I_VCVTPH2PS >::Test(list, is64); break;
            case I_VCVTPS2DQ:           encoder::Opcode$< I_VCVTPS2DQ >::Test(list, is64); break;
            case I_VCVTPS2PD:           encoder::Opcode$< I_VCVTPS2PD >::Test(list, is64); break;
            case I_VCVTPS2PH:           encoder::Opcode$< I_VCVTPS2PH >::Test(list, is64); break;
            case I_VCVTPS2UDQ:          encoder::Opcode$< I_VCVTPS2UDQ >::Test(list, is64); break;
            case I_VCVTSD2SI:           encoder::Opcode$< I_VCVTSD2SI >::Test(list, is64); break;
            case I_VCVTSD2SS:           encoder::Opcode$< I_VCVTSD2SS >::Test(list, is64); break;
            case I_VCVTSD2USI:          encoder::Opcode$< I_VCVTSD2USI >::Test(list, is64); break;
            case I_VCVTSI2SD:           encoder::Opcode$< I_VCVTSI2SD >::Test(list, is64); break;
            case I_VCVTSI2SS:           encoder::Opcode$< I_VCVTSI2SS >::Test(list, is64); break;
            case I_VCVTSS2SD:           encoder::Opcode$< I_VCVTSS2SD >::Test(list, is64); break;
            case I_VCVTSS2SI:           encoder::Opcode$< I_VCVTSS2SI >::Test(list, is64); break;
            case I_VCVTSS2USI:          encoder::Opcode$< I_VCVTSS2USI >::Test(list, is64); break;
            case I_VCVTTPD2DQ:          encoder::Opcode$< I_VCVTTPD2DQ >::Test(list, is64); break;
            case I_VCVTTPD2DQX:         encoder::Opcode$< I_VCVTTPD2DQX >::Test(list, is64); break;
            case I_VCVTTPD2UDQ:         encoder::Opcode$< I_VCVTTPD2UDQ >::Test(list, is64); break;
            case I_VCVTTPS2DQ:          encoder::Opcode$< I_VCVTTPS2DQ >::Test(list, is64); break;
            case I_VCVTTPS2UDQ:         encoder::Opcode$< I_VCVTTPS2UDQ >::Test(list, is64); break;
            case I_VCVTTSD2SI:          encoder::Opcode$< I_VCVTTSD2SI >::Test(list, is64); break;
            case I_VCVTTSD2USI:         encoder::Opcode$< I_VCVTTSD2USI >::Test(list, is64); break;
            case I_VCVTTSS2SI:          encoder::Opcode$< I_VCVTTSS2SI >::Test(list, is64); break;
            case I_VCVTTSS2USI:         encoder::Opcode$< I_VCVTTSS2USI >::Test(list, is64); break;
            case I_VCVTUDQ2PD:          encoder::Opcode$< I_VCVTUDQ2PD >::Test(list, is64); break;
            case I_VCVTUDQ2PS:          encoder::Opcode$< I_VCVTUDQ2PS >::Test(list, is64); break;
            case I_VCVTUSI2SD:          encoder::Opcode$< I_VCVTUSI2SD >::Test(list, is64); break;
            case I_VCVTUSI2SS:          encoder::Opcode$< I_VCVTUSI2SS >::Test(list, is64); break;
            case I_VDIVPD:              encoder::Opcode$< I_VDIVPD >::Test(list, is64); break;
            case I_VDIVPS:              encoder::Opcode$< I_VDIVPS >::Test(list, is64); break;
            case I_VDIVSD:              encoder::Opcode$< I_VDIVSD >::Test(list, is64); break;
            case I_VDIVSS:              encoder::Opcode$< I_VDIVSS >::Test(list, is64); break;
            case I_VDPPD:               encoder::Opcode$< I_VDPPD >::Test(list, is64); break;
            case I_VDPPS:               encoder::Opcode$< I_VDPPS >::Test(list, is64); break;
            case I_VERR:                encoder::Opcode$< I_VERR >::Test(list, is64); break;
            case I_VERW:                encoder::Opcode$< I_VERW >::Test(list, is64); break;
            case I_VEXTRACTF128:        encoder::Opcode$< I_VEXTRACTF128 >::Test(list, is64); break;
            case I_VEXTRACTF32X4:       encoder::Opcode$< I_VEXTRACTF32X4 >::Test(list, is64); break;
            case I_VEXTRACTF64X4:       encoder::Opcode$< I_VEXTRACTF64X4 >::Test(list, is64); break;
            case I_VEXTRACTI128:        encoder::Opcode$< I_VEXTRACTI128 >::Test(list, is64); break;
            case I_VEXTRACTI32X4:       encoder::Opcode$< I_VEXTRACTI32X4 >::Test(list, is64); break;
            case I_VEXTRACTI64X4:       encoder::Opcode$< I_VEXTRACTI64X4 >::Test(list, is64); break;
            case I_VEXTRACTPS:          encoder::Opcode$< I_VEXTRACTPS >::Test(list, is64); break;
            case I_VFMADD132PD:         encoder::Opcode$< I_VFMADD132PD >::Test(list, is64); break;
            case I_VFMADD132PS:         encoder::Opcode$< I_VFMADD132PS >::Test(list, is64); break;
            case I_VFMADD132SD:         encoder::Opcode$< I_VFMADD132SD >::Test(list, is64); break;
            case I_VFMADD132SS:         encoder::Opcode$< I_VFMADD132SS >::Test(list, is64); break;
            case I_VFMADD213PD:         encoder::Opcode$< I_VFMADD213PD >::Test(list, is64); break;
            case I_VFMADD213PS:         encoder::Opcode$< I_VFMADD213PS >::Test(list, is64); break;
            case I_VFMADD213SD:         encoder::Opcode$< I_VFMADD213SD >::Test(list, is64); break;
            case I_VFMADD213SS:         encoder::Opcode$< I_VFMADD213SS >::Test(list, is64); break;
            case I_VFMADD231PD:         encoder::Opcode$< I_VFMADD231PD >::Test(list, is64); break;
            case I_VFMADD231PS:         encoder::Opcode$< I_VFMADD231PS >::Test(list, is64); break;
            case I_VFMADD231SD:         encoder::Opcode$< I_VFMADD231SD >::Test(list, is64); break;
            case I_VFMADD231SS:         encoder::Opcode$< I_VFMADD231SS >::Test(list, is64); break;
            case I_VFMADDPD:            encoder::Opcode$< I_VFMADDPD >::Test(list, is64); break;
            case I_VFMADDPS:            encoder::Opcode$< I_VFMADDPS >::Test(list, is64); break;
            case I_VFMADDSD:            encoder::Opcode$< I_VFMADDSD >::Test(list, is64); break;
            case I_VFMADDSS:            encoder::Opcode$< I_VFMADDSS >::Test(list, is64); break;
            case I_VFMADDSUB132PD:      encoder::Opcode$< I_VFMADDSUB132PD >::Test(list, is64); break;
            case I_VFMADDSUB132PS:      encoder::Opcode$< I_VFMADDSUB132PS >::Test(list, is64); break;
            case I_VFMADDSUB213PD:      encoder::Opcode$< I_VFMADDSUB213PD >::Test(list, is64); break;
            case I_VFMADDSUB213PS:      encoder::Opcode$< I_VFMADDSUB213PS >::Test(list, is64); break;
            case I_VFMADDSUB231PD:      encoder::Opcode$< I_VFMADDSUB231PD >::Test(list, is64); break;
            case I_VFMADDSUB231PS:      encoder::Opcode$< I_VFMADDSUB231PS >::Test(list, is64); break;
            case I_VFMADDSUBPD:         encoder::Opcode$< I_VFMADDSUBPD >::Test(list, is64); break;
            case I_VFMADDSUBPS:         encoder::Opcode$< I_VFMADDSUBPS >::Test(list, is64); break;
            case I_VFMSUB132PD:         encoder::Opcode$< I_VFMSUB132PD >::Test(list, is64); break;
            case I_VFMSUB132PS:         encoder::Opcode$< I_VFMSUB132PS >::Test(list, is64); break;
            case I_VFMSUB132SD:         encoder::Opcode$< I_VFMSUB132SD >::Test(list, is64); break;
            case I_VFMSUB132SS:         encoder::Opcode$< I_VFMSUB132SS >::Test(list, is64); break;
            case I_VFMSUB213PD:         encoder::Opcode$< I_VFMSUB213PD >::Test(list, is64); break;
            case I_VFMSUB213PS:         encoder::Opcode$< I_VFMSUB213PS >::Test(list, is64); break;
            case I_VFMSUB213SD:         encoder::Opcode$< I_VFMSUB213SD >::Test(list, is64); break;
            case I_VFMSUB213SS:         encoder::Opcode$< I_VFMSUB213SS >::Test(list, is64); break;
            case I_VFMSUB231PD:         encoder::Opcode$< I_VFMSUB231PD >::Test(list, is64); break;
            case I_VFMSUB231PS:         encoder::Opcode$< I_VFMSUB231PS >::Test(list, is64); break;
            case I_VFMSUB231SD:         encoder::Opcode$< I_VFMSUB231SD >::Test(list, is64); break;
            case I_VFMSUB231SS:         encoder::Opcode$< I_VFMSUB231SS >::Test(list, is64); break;
            case I_VFMSUBADD132PD:      encoder::Opcode$< I_VFMSUBADD132PD >::Test(list, is64); break;
            case I_VFMSUBADD132PS:      encoder::Opcode$< I_VFMSUBADD132PS >::Test(list, is64); break;
            case I_VFMSUBADD213PD:      encoder::Opcode$< I_VFMSUBADD213PD >::Test(list, is64); break;
            case I_VFMSUBADD213PS:      encoder::Opcode$< I_VFMSUBADD213PS >::Test(list, is64); break;
            case I_VFMSUBADD231PD:      encoder::Opcode$< I_VFMSUBADD231PD >::Test(list, is64); break;
            case I_VFMSUBADD231PS:      encoder::Opcode$< I_VFMSUBADD231PS >::Test(list, is64); break;
            case I_VFMSUBADDPD:         encoder::Opcode$< I_VFMSUBADDPD >::Test(list, is64); break;
            case I_VFMSUBADDPS:         encoder::Opcode$< I_VFMSUBADDPS >::Test(list, is64); break;
            case I_VFMSUBPD:            encoder::Opcode$< I_VFMSUBPD >::Test(list, is64); break;
            case I_VFMSUBPS:            encoder::Opcode$< I_VFMSUBPS >::Test(list, is64); break;
            case I_VFMSUBSD:            encoder::Opcode$< I_VFMSUBSD >::Test(list, is64); break;
            case I_VFMSUBSS:            encoder::Opcode$< I_VFMSUBSS >::Test(list, is64); break;
            case I_VFNMADD132PD:        encoder::Opcode$< I_VFNMADD132PD >::Test(list, is64); break;
            case I_VFNMADD132PS:        encoder::Opcode$< I_VFNMADD132PS >::Test(list, is64); break;
            case I_VFNMADD132SD:        encoder::Opcode$< I_VFNMADD132SD >::Test(list, is64); break;
            case I_VFNMADD132SS:        encoder::Opcode$< I_VFNMADD132SS >::Test(list, is64); break;
            case I_VFNMADD213PD:        encoder::Opcode$< I_VFNMADD213PD >::Test(list, is64); break;
            case I_VFNMADD213PS:        encoder::Opcode$< I_VFNMADD213PS >::Test(list, is64); break;
            case I_VFNMADD213SD:        encoder::Opcode$< I_VFNMADD213SD >::Test(list, is64); break;
            case I_VFNMADD213SS:        encoder::Opcode$< I_VFNMADD213SS >::Test(list, is64); break;
            case I_VFNMADD231PD:        encoder::Opcode$< I_VFNMADD231PD >::Test(list, is64); break;
            case I_VFNMADD231PS:        encoder::Opcode$< I_VFNMADD231PS >::Test(list, is64); break;
            case I_VFNMADD231SD:        encoder::Opcode$< I_VFNMADD231SD >::Test(list, is64); break;
            case I_VFNMADD231SS:        encoder::Opcode$< I_VFNMADD231SS >::Test(list, is64); break;
            case I_VFNMADDPD:           encoder::Opcode$< I_VFNMADDPD >::Test(list, is64); break;
            case I_VFNMADDPS:           encoder::Opcode$< I_VFNMADDPS >::Test(list, is64); break;
            case I_VFNMADDSD:           encoder::Opcode$< I_VFNMADDSD >::Test(list, is64); break;
            case I_VFNMADDSS:           encoder::Opcode$< I_VFNMADDSS >::Test(list, is64); break;
            case I_VFNMSUB132PD:        encoder::Opcode$< I_VFNMSUB132PD >::Test(list, is64); break;
            case I_VFNMSUB132PS:        encoder::Opcode$< I_VFNMSUB132PS >::Test(list, is64); break;
            case I_VFNMSUB132SD:        encoder::Opcode$< I_VFNMSUB132SD >::Test(list, is64); break;
            case I_VFNMSUB132SS:        encoder::Opcode$< I_VFNMSUB132SS >::Test(list, is64); break;
            case I_VFNMSUB213PD:        encoder::Opcode$< I_VFNMSUB213PD >::Test(list, is64); break;
            case I_VFNMSUB213PS:        encoder::Opcode$< I_VFNMSUB213PS >::Test(list, is64); break;
            case I_VFNMSUB213SD:        encoder::Opcode$< I_VFNMSUB213SD >::Test(list, is64); break;
            case I_VFNMSUB213SS:        encoder::Opcode$< I_VFNMSUB213SS >::Test(list, is64); break;
            case I_VFNMSUB231PD:        encoder::Opcode$< I_VFNMSUB231PD >::Test(list, is64); break;
            case I_VFNMSUB231PS:        encoder::Opcode$< I_VFNMSUB231PS >::Test(list, is64); break;
            case I_VFNMSUB231SD:        encoder::Opcode$< I_VFNMSUB231SD >::Test(list, is64); break;
            case I_VFNMSUB231SS:        encoder::Opcode$< I_VFNMSUB231SS >::Test(list, is64); break;
            case I_VFNMSUBPD:           encoder::Opcode$< I_VFNMSUBPD >::Test(list, is64); break;
            case I_VFNMSUBPS:           encoder::Opcode$< I_VFNMSUBPS >::Test(list, is64); break;
            case I_VFNMSUBSD:           encoder::Opcode$< I_VFNMSUBSD >::Test(list, is64); break;
            case I_VFNMSUBSS:           encoder::Opcode$< I_VFNMSUBSS >::Test(list, is64); break;
            case I_VFRCZPD:             encoder::Opcode$< I_VFRCZPD >::Test(list, is64); break;
            case I_VFRCZPS:             encoder::Opcode$< I_VFRCZPS >::Test(list, is64); break;
            case I_VFRCZSD:             encoder::Opcode$< I_VFRCZSD >::Test(list, is64); break;
            case I_VFRCZSS:             encoder::Opcode$< I_VFRCZSS >::Test(list, is64); break;
            case I_VGATHERDPD:          encoder::Opcode$< I_VGATHERDPD >::Test(list, is64); break;
            case I_VGATHERDPS:          encoder::Opcode$< I_VGATHERDPS >::Test(list, is64); break;
            case I_VGATHERPF0DPD:       encoder::Opcode$< I_VGATHERPF0DPD >::Test(list, is64); break;
            case I_VGATHERPF0DPS:       encoder::Opcode$< I_VGATHERPF0DPS >::Test(list, is64); break;
            case I_VGATHERPF0QPD:       encoder::Opcode$< I_VGATHERPF0QPD >::Test(list, is64); break;
            case I_VGATHERPF0QPS:       encoder::Opcode$< I_VGATHERPF0QPS >::Test(list, is64); break;
            case I_VGATHERPF1DPD:       encoder::Opcode$< I_VGATHERPF1DPD >::Test(list, is64); break;
            case I_VGATHERPF1DPS:       encoder::Opcode$< I_VGATHERPF1DPS >::Test(list, is64); break;
            case I_VGATHERPF1QPD:       encoder::Opcode$< I_VGATHERPF1QPD >::Test(list, is64); break;
            case I_VGATHERPF1QPS:       encoder::Opcode$< I_VGATHERPF1QPS >::Test(list, is64); break;
            case I_VGATHERQPD:          encoder::Opcode$< I_VGATHERQPD >::Test(list, is64); break;
            case I_VGATHERQPS:          encoder::Opcode$< I_VGATHERQPS >::Test(list, is64); break;
            case I_VHADDPD:             encoder::Opcode$< I_VHADDPD >::Test(list, is64); break;
            case I_VHADDPS:             encoder::Opcode$< I_VHADDPS >::Test(list, is64); break;
            case I_VHSUBPD:             encoder::Opcode$< I_VHSUBPD >::Test(list, is64); break;
            case I_VHSUBPS:             encoder::Opcode$< I_VHSUBPS >::Test(list, is64); break;
            case I_VINSERTF128:         encoder::Opcode$< I_VINSERTF128 >::Test(list, is64); break;
            case I_VINSERTF32X4:        encoder::Opcode$< I_VINSERTF32X4 >::Test(list, is64); break;
            case I_VINSERTF64X4:        encoder::Opcode$< I_VINSERTF64X4 >::Test(list, is64); break;
            case I_VINSERTI128:         encoder::Opcode$< I_VINSERTI128 >::Test(list, is64); break;
            case I_VINSERTI32X4:        encoder::Opcode$< I_VINSERTI32X4 >::Test(list, is64); break;
            case I_VINSERTI64X4:        encoder::Opcode$< I_VINSERTI64X4 >::Test(list, is64); break;
            case I_VINSERTPS:           encoder::Opcode$< I_VINSERTPS >::Test(list, is64); break;
            case I_VLDDQU:              encoder::Opcode$< I_VLDDQU >::Test(list, is64); break;
            case I_VLDMXCSR:            encoder::Opcode$< I_VLDMXCSR >::Test(list, is64); break;
            case I_VMASKMOVDQU:         encoder::Opcode$< I_VMASKMOVDQU >::Test(list, is64); break;
            case I_VMASKMOVPD:          encoder::Opcode$< I_VMASKMOVPD >::Test(list, is64); break;
            case I_VMASKMOVPS:          encoder::Opcode$< I_VMASKMOVPS >::Test(list, is64); break;
            case I_VMAXPD:              encoder::Opcode$< I_VMAXPD >::Test(list, is64); break;
            case I_VMAXPS:              encoder::Opcode$< I_VMAXPS >::Test(list, is64); break;
            case I_VMAXSD:              encoder::Opcode$< I_VMAXSD >::Test(list, is64); break;
            case I_VMAXSS:              encoder::Opcode$< I_VMAXSS >::Test(list, is64); break;
            case I_VMCALL:              encoder::Opcode$< I_VMCALL >::Test(list, is64); break;
            case I_VMCLEAR:             encoder::Opcode$< I_VMCLEAR >::Test(list, is64); break;
            case I_VMFUNC:              encoder::Opcode$< I_VMFUNC >::Test(list, is64); break;
            case I_VMINPD:              encoder::Opcode$< I_VMINPD >::Test(list, is64); break;
            case I_VMINPS:              encoder::Opcode$< I_VMINPS >::Test(list, is64); break;
            case I_VMINSD:              encoder::Opcode$< I_VMINSD >::Test(list, is64); break;
            case I_VMINSS:              encoder::Opcode$< I_VMINSS >::Test(list, is64); break;
            case I_VMLAUNCH:            encoder::Opcode$< I_VMLAUNCH >::Test(list, is64); break;
            case I_VMLOAD:              encoder::Opcode$< I_VMLOAD >::Test(list, is64); break;
            case I_VMMCALL:             encoder::Opcode$< I_VMMCALL >::Test(list, is64); break;
            case I_VMOVAPD:             encoder::Opcode$< I_VMOVAPD >::Test(list, is64); break;
            case I_VMOVAPS:             encoder::Opcode$< I_VMOVAPS >::Test(list, is64); break;
            case I_VMOVD:               encoder::Opcode$< I_VMOVD >::Test(list, is64); break;
            case I_VMOVDDUP:            encoder::Opcode$< I_VMOVDDUP >::Test(list, is64); break;
            case I_VMOVDQA:             encoder::Opcode$< I_VMOVDQA >::Test(list, is64); break;
            case I_VMOVDQA32:           encoder::Opcode$< I_VMOVDQA32 >::Test(list, is64); break;
            case I_VMOVDQA64:           encoder::Opcode$< I_VMOVDQA64 >::Test(list, is64); break;
            case I_VMOVDQU:             encoder::Opcode$< I_VMOVDQU >::Test(list, is64); break;
            case I_VMOVDQU16:           encoder::Opcode$< I_VMOVDQU16 >::Test(list, is64); break;
            case I_VMOVDQU32:           encoder::Opcode$< I_VMOVDQU32 >::Test(list, is64); break;
            case I_VMOVDQU64:           encoder::Opcode$< I_VMOVDQU64 >::Test(list, is64); break;
            case I_VMOVDQU8:            encoder::Opcode$< I_VMOVDQU8 >::Test(list, is64); break;
            case I_VMOVHLPS:            encoder::Opcode$< I_VMOVHLPS >::Test(list, is64); break;
            case I_VMOVHPD:             encoder::Opcode$< I_VMOVHPD >::Test(list, is64); break;
            case I_VMOVHPS:             encoder::Opcode$< I_VMOVHPS >::Test(list, is64); break;
            case I_VMOVLHPS:            encoder::Opcode$< I_VMOVLHPS >::Test(list, is64); break;
            case I_VMOVLPD:             encoder::Opcode$< I_VMOVLPD >::Test(list, is64); break;
            case I_VMOVLPS:             encoder::Opcode$< I_VMOVLPS >::Test(list, is64); break;
            case I_VMOVMSKPD:           encoder::Opcode$< I_VMOVMSKPD >::Test(list, is64); break;
            case I_VMOVMSKPS:           encoder::Opcode$< I_VMOVMSKPS >::Test(list, is64); break;
            case I_VMOVNTDQ:            encoder::Opcode$< I_VMOVNTDQ >::Test(list, is64); break;
            case I_VMOVNTDQA:           encoder::Opcode$< I_VMOVNTDQA >::Test(list, is64); break;
            case I_VMOVNTPD:            encoder::Opcode$< I_VMOVNTPD >::Test(list, is64); break;
            case I_VMOVNTPS:            encoder::Opcode$< I_VMOVNTPS >::Test(list, is64); break;
            case I_VMOVQ:               encoder::Opcode$< I_VMOVQ >::Test(list, is64); break;
            case I_VMOVSD:              encoder::Opcode$< I_VMOVSD >::Test(list, is64); break;
            case I_VMOVSHDUP:           encoder::Opcode$< I_VMOVSHDUP >::Test(list, is64); break;
            case I_VMOVSLDUP:           encoder::Opcode$< I_VMOVSLDUP >::Test(list, is64); break;
            case I_VMOVSS:              encoder::Opcode$< I_VMOVSS >::Test(list, is64); break;
            case I_VMOVUPD:             encoder::Opcode$< I_VMOVUPD >::Test(list, is64); break;
            case I_VMOVUPS:             encoder::Opcode$< I_VMOVUPS >::Test(list, is64); break;
            case I_VMPSADBW:            encoder::Opcode$< I_VMPSADBW >::Test(list, is64); break;
            case I_VMPTRLD:             encoder::Opcode$< I_VMPTRLD >::Test(list, is64); break;
            case I_VMPTRST:             encoder::Opcode$< I_VMPTRST >::Test(list, is64); break;
            case I_VMREAD:              encoder::Opcode$< I_VMREAD >::Test(list, is64); break;
            case I_VMRESUME:            encoder::Opcode$< I_VMRESUME >::Test(list, is64); break;
            case I_VMRUN:               encoder::Opcode$< I_VMRUN >::Test(list, is64); break;
            case I_VMSAVE:              encoder::Opcode$< I_VMSAVE >::Test(list, is64); break;
            case I_VMULPD:              encoder::Opcode$< I_VMULPD >::Test(list, is64); break;
            case I_VMULPS:              encoder::Opcode$< I_VMULPS >::Test(list, is64); break;
            case I_VMULSD:              encoder::Opcode$< I_VMULSD >::Test(list, is64); break;
            case I_VMULSS:              encoder::Opcode$< I_VMULSS >::Test(list, is64); break;
            case I_VMWRITE:             encoder::Opcode$< I_VMWRITE >::Test(list, is64); break;
            case I_VMXOFF:              encoder::Opcode$< I_VMXOFF >::Test(list, is64); break;
            case I_VMXON:               encoder::Opcode$< I_VMXON >::Test(list, is64); break;
            case I_VORPD:               encoder::Opcode$< I_VORPD >::Test(list, is64); break;
            case I_VORPS:               encoder::Opcode$< I_VORPS >::Test(list, is64); break;
            case I_VPABSB:              encoder::Opcode$< I_VPABSB >::Test(list, is64); break;
            case I_VPABSD:              encoder::Opcode$< I_VPABSD >::Test(list, is64); break;
            case I_VPABSQ:              encoder::Opcode$< I_VPABSQ >::Test(list, is64); break;
            case I_VPABSW:              encoder::Opcode$< I_VPABSW >::Test(list, is64); break;
            case I_VPACKSSDW:           encoder::Opcode$< I_VPACKSSDW >::Test(list, is64); break;
            case I_VPACKSSWB:           encoder::Opcode$< I_VPACKSSWB >::Test(list, is64); break;
            case I_VPACKUSDW:           encoder::Opcode$< I_VPACKUSDW >::Test(list, is64); break;
            case I_VPACKUSWB:           encoder::Opcode$< I_VPACKUSWB >::Test(list, is64); break;
            case I_VPADDB:              encoder::Opcode$< I_VPADDB >::Test(list, is64); break;
            case I_VPADDD:              encoder::Opcode$< I_VPADDD >::Test(list, is64); break;
            case I_VPADDQ:              encoder::Opcode$< I_VPADDQ >::Test(list, is64); break;
            case I_VPADDSB:             encoder::Opcode$< I_VPADDSB >::Test(list, is64); break;
            case I_VPADDSW:             encoder::Opcode$< I_VPADDSW >::Test(list, is64); break;
            case I_VPADDUSB:            encoder::Opcode$< I_VPADDUSB >::Test(list, is64); break;
            case I_VPADDUSW:            encoder::Opcode$< I_VPADDUSW >::Test(list, is64); break;
            case I_VPADDW:              encoder::Opcode$< I_VPADDW >::Test(list, is64); break;
            case I_VPALIGNR:            encoder::Opcode$< I_VPALIGNR >::Test(list, is64); break;
            case I_VPAND:               encoder::Opcode$< I_VPAND >::Test(list, is64); break;
            case I_VPANDD:              encoder::Opcode$< I_VPANDD >::Test(list, is64); break;
            case I_VPANDN:              encoder::Opcode$< I_VPANDN >::Test(list, is64); break;
            case I_VPANDND:             encoder::Opcode$< I_VPANDND >::Test(list, is64); break;
            case I_VPANDNQ:             encoder::Opcode$< I_VPANDNQ >::Test(list, is64); break;
            case I_VPANDQ:              encoder::Opcode$< I_VPANDQ >::Test(list, is64); break;
            case I_VPAVGB:              encoder::Opcode$< I_VPAVGB >::Test(list, is64); break;
            case I_VPAVGW:              encoder::Opcode$< I_VPAVGW >::Test(list, is64); break;
            case I_VPBLENDD:            encoder::Opcode$< I_VPBLENDD >::Test(list, is64); break;
            case I_VPBLENDMD:           encoder::Opcode$< I_VPBLENDMD >::Test(list, is64); break;
            case I_VPBLENDMQ:           encoder::Opcode$< I_VPBLENDMQ >::Test(list, is64); break;
            case I_VPBLENDVB:           encoder::Opcode$< I_VPBLENDVB >::Test(list, is64); break;
            case I_VPBLENDW:            encoder::Opcode$< I_VPBLENDW >::Test(list, is64); break;
            case I_VPBROADCASTB:        encoder::Opcode$< I_VPBROADCASTB >::Test(list, is64); break;
            case I_VPBROADCASTD:        encoder::Opcode$< I_VPBROADCASTD >::Test(list, is64); break;
            case I_VPBROADCASTMB2Q:     encoder::Opcode$< I_VPBROADCASTMB2Q >::Test(list, is64); break;
            case I_VPBROADCASTMW2D:     encoder::Opcode$< I_VPBROADCASTMW2D >::Test(list, is64); break;
            case I_VPBROADCASTQ:        encoder::Opcode$< I_VPBROADCASTQ >::Test(list, is64); break;
            case I_VPBROADCASTW:        encoder::Opcode$< I_VPBROADCASTW >::Test(list, is64); break;
            case I_VPCLMULQDQ:          encoder::Opcode$< I_VPCLMULQDQ >::Test(list, is64); break;
            case I_VPCMOV:              encoder::Opcode$< I_VPCMOV >::Test(list, is64); break;
            case I_VPCMP:               encoder::Opcode$< I_VPCMP >::Test(list, is64); break;
            case I_VPCMPD:              encoder::Opcode$< I_VPCMPD >::Test(list, is64); break;
            case I_VPCMPEQB:            encoder::Opcode$< I_VPCMPEQB >::Test(list, is64); break;
            case I_VPCMPEQD:            encoder::Opcode$< I_VPCMPEQD >::Test(list, is64); break;
            case I_VPCMPEQQ:            encoder::Opcode$< I_VPCMPEQQ >::Test(list, is64); break;
            case I_VPCMPEQW:            encoder::Opcode$< I_VPCMPEQW >::Test(list, is64); break;
            case I_VPCMPESTRI:          encoder::Opcode$< I_VPCMPESTRI >::Test(list, is64); break;
            case I_VPCMPESTRM:          encoder::Opcode$< I_VPCMPESTRM >::Test(list, is64); break;
            case I_VPCMPGTB:            encoder::Opcode$< I_VPCMPGTB >::Test(list, is64); break;
            case I_VPCMPGTD:            encoder::Opcode$< I_VPCMPGTD >::Test(list, is64); break;
            case I_VPCMPGTQ:            encoder::Opcode$< I_VPCMPGTQ >::Test(list, is64); break;
            case I_VPCMPGTW:            encoder::Opcode$< I_VPCMPGTW >::Test(list, is64); break;
            case I_VPCMPISTRI:          encoder::Opcode$< I_VPCMPISTRI >::Test(list, is64); break;
            case I_VPCMPISTRM:          encoder::Opcode$< I_VPCMPISTRM >::Test(list, is64); break;
            case I_VPCMPQ:              encoder::Opcode$< I_VPCMPQ >::Test(list, is64); break;
            case I_VPCMPUD:             encoder::Opcode$< I_VPCMPUD >::Test(list, is64); break;
            case I_VPCMPUQ:             encoder::Opcode$< I_VPCMPUQ >::Test(list, is64); break;
            case I_VPCOMB:              encoder::Opcode$< I_VPCOMB >::Test(list, is64); break;
            case I_VPCOMD:              encoder::Opcode$< I_VPCOMD >::Test(list, is64); break;
            case I_VPCOMQ:              encoder::Opcode$< I_VPCOMQ >::Test(list, is64); break;
            case I_VPCOMUB:             encoder::Opcode$< I_VPCOMUB >::Test(list, is64); break;
            case I_VPCOMUD:             encoder::Opcode$< I_VPCOMUD >::Test(list, is64); break;
            case I_VPCOMUQ:             encoder::Opcode$< I_VPCOMUQ >::Test(list, is64); break;
            case I_VPCOMUW:             encoder::Opcode$< I_VPCOMUW >::Test(list, is64); break;
            case I_VPCOMW:              encoder::Opcode$< I_VPCOMW >::Test(list, is64); break;
            case I_VPCONFLICTD:         encoder::Opcode$< I_VPCONFLICTD >::Test(list, is64); break;
            case I_VPCONFLICTQ:         encoder::Opcode$< I_VPCONFLICTQ >::Test(list, is64); break;
            case I_VPERM2F128:          encoder::Opcode$< I_VPERM2F128 >::Test(list, is64); break;
            case I_VPERM2I128:          encoder::Opcode$< I_VPERM2I128 >::Test(list, is64); break;
            case I_VPERMD:              encoder::Opcode$< I_VPERMD >::Test(list, is64); break;
            case I_VPERMI2D:            encoder::Opcode$< I_VPERMI2D >::Test(list, is64); break;
            case I_VPERMI2PD:           encoder::Opcode$< I_VPERMI2PD >::Test(list, is64); break;
            case I_VPERMI2PS:           encoder::Opcode$< I_VPERMI2PS >::Test(list, is64); break;
            case I_VPERMI2Q:            encoder::Opcode$< I_VPERMI2Q >::Test(list, is64); break;
            case I_VPERMIL2PD:          encoder::Opcode$< I_VPERMIL2PD >::Test(list, is64); break;
            case I_VPERMIL2PS:          encoder::Opcode$< I_VPERMIL2PS >::Test(list, is64); break;
            case I_VPERMILPD:           encoder::Opcode$< I_VPERMILPD >::Test(list, is64); break;
            case I_VPERMILPS:           encoder::Opcode$< I_VPERMILPS >::Test(list, is64); break;
            case I_VPERMPD:             encoder::Opcode$< I_VPERMPD >::Test(list, is64); break;
            case I_VPERMPS:             encoder::Opcode$< I_VPERMPS >::Test(list, is64); break;
            case I_VPERMQ:              encoder::Opcode$< I_VPERMQ >::Test(list, is64); break;
            case I_VPERMT2D:            encoder::Opcode$< I_VPERMT2D >::Test(list, is64); break;
            case I_VPERMT2PD:           encoder::Opcode$< I_VPERMT2PD >::Test(list, is64); break;
            case I_VPERMT2PS:           encoder::Opcode$< I_VPERMT2PS >::Test(list, is64); break;
            case I_VPERMT2Q:            encoder::Opcode$< I_VPERMT2Q >::Test(list, is64); break;
            case I_VPEXTRB:             encoder::Opcode$< I_VPEXTRB >::Test(list, is64); break;
            case I_VPEXTRD:             encoder::Opcode$< I_VPEXTRD >::Test(list, is64); break;
            case I_VPEXTRQ:             encoder::Opcode$< I_VPEXTRQ >::Test(list, is64); break;
            case I_VPEXTRW:             encoder::Opcode$< I_VPEXTRW >::Test(list, is64); break;
            case I_VPGATHERDD:          encoder::Opcode$< I_VPGATHERDD >::Test(list, is64); break;
            case I_VPGATHERDQ:          encoder::Opcode$< I_VPGATHERDQ >::Test(list, is64); break;
            case I_VPGATHERQD:          encoder::Opcode$< I_VPGATHERQD >::Test(list, is64); break;
            case I_VPGATHERQQ:          encoder::Opcode$< I_VPGATHERQQ >::Test(list, is64); break;
            case I_VPHADDBD:            encoder::Opcode$< I_VPHADDBD >::Test(list, is64); break;
            case I_VPHADDBQ:            encoder::Opcode$< I_VPHADDBQ >::Test(list, is64); break;
            case I_VPHADDBW:            encoder::Opcode$< I_VPHADDBW >::Test(list, is64); break;
            case I_VPHADDD:             encoder::Opcode$< I_VPHADDD >::Test(list, is64); break;
            case I_VPHADDDQ:            encoder::Opcode$< I_VPHADDDQ >::Test(list, is64); break;
            case I_VPHADDSW:            encoder::Opcode$< I_VPHADDSW >::Test(list, is64); break;
            case I_VPHADDUBD:           encoder::Opcode$< I_VPHADDUBD >::Test(list, is64); break;
            case I_VPHADDUBQ:           encoder::Opcode$< I_VPHADDUBQ >::Test(list, is64); break;
            case I_VPHADDUBW:           encoder::Opcode$< I_VPHADDUBW >::Test(list, is64); break;
            case I_VPHADDUDQ:           encoder::Opcode$< I_VPHADDUDQ >::Test(list, is64); break;
            case I_VPHADDUWD:           encoder::Opcode$< I_VPHADDUWD >::Test(list, is64); break;
            case I_VPHADDUWQ:           encoder::Opcode$< I_VPHADDUWQ >::Test(list, is64); break;
            case I_VPHADDW:             encoder::Opcode$< I_VPHADDW >::Test(list, is64); break;
            case I_VPHADDWD:            encoder::Opcode$< I_VPHADDWD >::Test(list, is64); break;
            case I_VPHADDWQ:            encoder::Opcode$< I_VPHADDWQ >::Test(list, is64); break;
            case I_VPHMINPOSUW:         encoder::Opcode$< I_VPHMINPOSUW >::Test(list, is64); break;
            case I_VPHSUBBW:            encoder::Opcode$< I_VPHSUBBW >::Test(list, is64); break;
            case I_VPHSUBD:             encoder::Opcode$< I_VPHSUBD >::Test(list, is64); break;
            case I_VPHSUBDQ:            encoder::Opcode$< I_VPHSUBDQ >::Test(list, is64); break;
            case I_VPHSUBSW:            encoder::Opcode$< I_VPHSUBSW >::Test(list, is64); break;
            case I_VPHSUBW:             encoder::Opcode$< I_VPHSUBW >::Test(list, is64); break;
            case I_VPHSUBWD:            encoder::Opcode$< I_VPHSUBWD >::Test(list, is64); break;
            case I_VPINSRB:             encoder::Opcode$< I_VPINSRB >::Test(list, is64); break;
            case I_VPINSRD:             encoder::Opcode$< I_VPINSRD >::Test(list, is64); break;
            case I_VPINSRQ:             encoder::Opcode$< I_VPINSRQ >::Test(list, is64); break;
            case I_VPINSRW:             encoder::Opcode$< I_VPINSRW >::Test(list, is64); break;
            case I_VPLZCNTD:            encoder::Opcode$< I_VPLZCNTD >::Test(list, is64); break;
            case I_VPLZCNTQ:            encoder::Opcode$< I_VPLZCNTQ >::Test(list, is64); break;
            case I_VPMACSDD:            encoder::Opcode$< I_VPMACSDD >::Test(list, is64); break;
            case I_VPMACSDQH:           encoder::Opcode$< I_VPMACSDQH >::Test(list, is64); break;
            case I_VPMACSDQL:           encoder::Opcode$< I_VPMACSDQL >::Test(list, is64); break;
            case I_VPMACSSDD:           encoder::Opcode$< I_VPMACSSDD >::Test(list, is64); break;
            case I_VPMACSSDQH:          encoder::Opcode$< I_VPMACSSDQH >::Test(list, is64); break;
            case I_VPMACSSDQL:          encoder::Opcode$< I_VPMACSSDQL >::Test(list, is64); break;
            case I_VPMACSSWD:           encoder::Opcode$< I_VPMACSSWD >::Test(list, is64); break;
            case I_VPMACSSWW:           encoder::Opcode$< I_VPMACSSWW >::Test(list, is64); break;
            case I_VPMACSWD:            encoder::Opcode$< I_VPMACSWD >::Test(list, is64); break;
            case I_VPMACSWW:            encoder::Opcode$< I_VPMACSWW >::Test(list, is64); break;
            case I_VPMADCSSWD:          encoder::Opcode$< I_VPMADCSSWD >::Test(list, is64); break;
            case I_VPMADCSWD:           encoder::Opcode$< I_VPMADCSWD >::Test(list, is64); break;
            case I_VPMADDUBSW:          encoder::Opcode$< I_VPMADDUBSW >::Test(list, is64); break;
            case I_VPMADDWD:            encoder::Opcode$< I_VPMADDWD >::Test(list, is64); break;
            case I_VPMASKMOVD:          encoder::Opcode$< I_VPMASKMOVD >::Test(list, is64); break;
            case I_VPMASKMOVQ:          encoder::Opcode$< I_VPMASKMOVQ >::Test(list, is64); break;
            case I_VPMAXSB:             encoder::Opcode$< I_VPMAXSB >::Test(list, is64); break;
            case I_VPMAXSD:             encoder::Opcode$< I_VPMAXSD >::Test(list, is64); break;
            case I_VPMAXSQ:             encoder::Opcode$< I_VPMAXSQ >::Test(list, is64); break;
            case I_VPMAXSW:             encoder::Opcode$< I_VPMAXSW >::Test(list, is64); break;
            case I_VPMAXUB:             encoder::Opcode$< I_VPMAXUB >::Test(list, is64); break;
            case I_VPMAXUD:             encoder::Opcode$< I_VPMAXUD >::Test(list, is64); break;
            case I_VPMAXUQ:             encoder::Opcode$< I_VPMAXUQ >::Test(list, is64); break;
            case I_VPMAXUW:             encoder::Opcode$< I_VPMAXUW >::Test(list, is64); break;
            case I_VPMINSB:             encoder::Opcode$< I_VPMINSB >::Test(list, is64); break;
            case I_VPMINSD:             encoder::Opcode$< I_VPMINSD >::Test(list, is64); break;
            case I_VPMINSQ:             encoder::Opcode$< I_VPMINSQ >::Test(list, is64); break;
            case I_VPMINSW:             encoder::Opcode$< I_VPMINSW >::Test(list, is64); break;
            case I_VPMINUB:             encoder::Opcode$< I_VPMINUB >::Test(list, is64); break;
            case I_VPMINUD:             encoder::Opcode$< I_VPMINUD >::Test(list, is64); break;
            case I_VPMINUQ:             encoder::Opcode$< I_VPMINUQ >::Test(list, is64); break;
            case I_VPMINUW:             encoder::Opcode$< I_VPMINUW >::Test(list, is64); break;
            case I_VPMOVDB:             encoder::Opcode$< I_VPMOVDB >::Test(list, is64); break;
            case I_VPMOVDW:             encoder::Opcode$< I_VPMOVDW >::Test(list, is64); break;
            case I_VPMOVMSKB:           encoder::Opcode$< I_VPMOVMSKB >::Test(list, is64); break;
            case I_VPMOVQB:             encoder::Opcode$< I_VPMOVQB >::Test(list, is64); break;
            case I_VPMOVQD:             encoder::Opcode$< I_VPMOVQD >::Test(list, is64); break;
            case I_VPMOVQW:             encoder::Opcode$< I_VPMOVQW >::Test(list, is64); break;
            case I_VPMOVSDB:            encoder::Opcode$< I_VPMOVSDB >::Test(list, is64); break;
            case I_VPMOVSDW:            encoder::Opcode$< I_VPMOVSDW >::Test(list, is64); break;
            case I_VPMOVSQB:            encoder::Opcode$< I_VPMOVSQB >::Test(list, is64); break;
            case I_VPMOVSQD:            encoder::Opcode$< I_VPMOVSQD >::Test(list, is64); break;
            case I_VPMOVSQW:            encoder::Opcode$< I_VPMOVSQW >::Test(list, is64); break;
            case I_VPMOVSXBD:           encoder::Opcode$< I_VPMOVSXBD >::Test(list, is64); break;
            case I_VPMOVSXBQ:           encoder::Opcode$< I_VPMOVSXBQ >::Test(list, is64); break;
            case I_VPMOVSXBW:           encoder::Opcode$< I_VPMOVSXBW >::Test(list, is64); break;
            case I_VPMOVSXDQ:           encoder::Opcode$< I_VPMOVSXDQ >::Test(list, is64); break;
            case I_VPMOVSXWD:           encoder::Opcode$< I_VPMOVSXWD >::Test(list, is64); break;
            case I_VPMOVSXWQ:           encoder::Opcode$< I_VPMOVSXWQ >::Test(list, is64); break;
            case I_VPMOVUSDB:           encoder::Opcode$< I_VPMOVUSDB >::Test(list, is64); break;
            case I_VPMOVUSDW:           encoder::Opcode$< I_VPMOVUSDW >::Test(list, is64); break;
            case I_VPMOVUSQB:           encoder::Opcode$< I_VPMOVUSQB >::Test(list, is64); break;
            case I_VPMOVUSQD:           encoder::Opcode$< I_VPMOVUSQD >::Test(list, is64); break;
            case I_VPMOVUSQW:           encoder::Opcode$< I_VPMOVUSQW >::Test(list, is64); break;
            case I_VPMOVZXBD:           encoder::Opcode$< I_VPMOVZXBD >::Test(list, is64); break;
            case I_VPMOVZXBQ:           encoder::Opcode$< I_VPMOVZXBQ >::Test(list, is64); break;
            case I_VPMOVZXBW:           encoder::Opcode$< I_VPMOVZXBW >::Test(list, is64); break;
            case I_VPMOVZXDQ:           encoder::Opcode$< I_VPMOVZXDQ >::Test(list, is64); break;
            case I_VPMOVZXWD:           encoder::Opcode$< I_VPMOVZXWD >::Test(list, is64); break;
            case I_VPMOVZXWQ:           encoder::Opcode$< I_VPMOVZXWQ >::Test(list, is64); break;
            case I_VPMULDQ:             encoder::Opcode$< I_VPMULDQ >::Test(list, is64); break;
            case I_VPMULHRSW:           encoder::Opcode$< I_VPMULHRSW >::Test(list, is64); break;
            case I_VPMULHUW:            encoder::Opcode$< I_VPMULHUW >::Test(list, is64); break;
            case I_VPMULHW:             encoder::Opcode$< I_VPMULHW >::Test(list, is64); break;
            case I_VPMULLD:             encoder::Opcode$< I_VPMULLD >::Test(list, is64); break;
            case I_VPMULLW:             encoder::Opcode$< I_VPMULLW >::Test(list, is64); break;
            case I_VPMULUDQ:            encoder::Opcode$< I_VPMULUDQ >::Test(list, is64); break;
            case I_VPOR:                encoder::Opcode$< I_VPOR >::Test(list, is64); break;
            case I_VPORD:               encoder::Opcode$< I_VPORD >::Test(list, is64); break;
            case I_VPORQ:               encoder::Opcode$< I_VPORQ >::Test(list, is64); break;
            case I_VPPERM:              encoder::Opcode$< I_VPPERM >::Test(list, is64); break;
            case I_VPROTB:              encoder::Opcode$< I_VPROTB >::Test(list, is64); break;
            case I_VPROTD:              encoder::Opcode$< I_VPROTD >::Test(list, is64); break;
            case I_VPROTQ:              encoder::Opcode$< I_VPROTQ >::Test(list, is64); break;
            case I_VPROTW:              encoder::Opcode$< I_VPROTW >::Test(list, is64); break;
            case I_VPSADBW:             encoder::Opcode$< I_VPSADBW >::Test(list, is64); break;
            case I_VPSCATTERDD:         encoder::Opcode$< I_VPSCATTERDD >::Test(list, is64); break;
            case I_VPSCATTERDQ:         encoder::Opcode$< I_VPSCATTERDQ >::Test(list, is64); break;
            case I_VPSCATTERQD:         encoder::Opcode$< I_VPSCATTERQD >::Test(list, is64); break;
            case I_VPSCATTERQQ:         encoder::Opcode$< I_VPSCATTERQQ >::Test(list, is64); break;
            case I_VPSHAB:              encoder::Opcode$< I_VPSHAB >::Test(list, is64); break;
            case I_VPSHAD:              encoder::Opcode$< I_VPSHAD >::Test(list, is64); break;
            case I_VPSHAQ:              encoder::Opcode$< I_VPSHAQ >::Test(list, is64); break;
            case I_VPSHAW:              encoder::Opcode$< I_VPSHAW >::Test(list, is64); break;
            case I_VPSHLB:              encoder::Opcode$< I_VPSHLB >::Test(list, is64); break;
            case I_VPSHLD:              encoder::Opcode$< I_VPSHLD >::Test(list, is64); break;
            case I_VPSHLQ:              encoder::Opcode$< I_VPSHLQ >::Test(list, is64); break;
            case I_VPSHLW:              encoder::Opcode$< I_VPSHLW >::Test(list, is64); break;
            case I_VPSHUFB:             encoder::Opcode$< I_VPSHUFB >::Test(list, is64); break;
            case I_VPSHUFD:             encoder::Opcode$< I_VPSHUFD >::Test(list, is64); break;
            case I_VPSHUFHW:            encoder::Opcode$< I_VPSHUFHW >::Test(list, is64); break;
            case I_VPSHUFLW:            encoder::Opcode$< I_VPSHUFLW >::Test(list, is64); break;
            case I_VPSIGNB:             encoder::Opcode$< I_VPSIGNB >::Test(list, is64); break;
            case I_VPSIGND:             encoder::Opcode$< I_VPSIGND >::Test(list, is64); break;
            case I_VPSIGNW:             encoder::Opcode$< I_VPSIGNW >::Test(list, is64); break;
            case I_VPSLLD:              encoder::Opcode$< I_VPSLLD >::Test(list, is64); break;
            case I_VPSLLDQ:             encoder::Opcode$< I_VPSLLDQ >::Test(list, is64); break;
            case I_VPSLLQ:              encoder::Opcode$< I_VPSLLQ >::Test(list, is64); break;
            case I_VPSLLVD:             encoder::Opcode$< I_VPSLLVD >::Test(list, is64); break;
            case I_VPSLLVQ:             encoder::Opcode$< I_VPSLLVQ >::Test(list, is64); break;
            case I_VPSLLW:              encoder::Opcode$< I_VPSLLW >::Test(list, is64); break;
            case I_VPSRAD:              encoder::Opcode$< I_VPSRAD >::Test(list, is64); break;
            case I_VPSRAQ:              encoder::Opcode$< I_VPSRAQ >::Test(list, is64); break;
            case I_VPSRAVD:             encoder::Opcode$< I_VPSRAVD >::Test(list, is64); break;
            case I_VPSRAVQ:             encoder::Opcode$< I_VPSRAVQ >::Test(list, is64); break;
            case I_VPSRAW:              encoder::Opcode$< I_VPSRAW >::Test(list, is64); break;
            case I_VPSRLD:              encoder::Opcode$< I_VPSRLD >::Test(list, is64); break;
            case I_VPSRLDQ:             encoder::Opcode$< I_VPSRLDQ >::Test(list, is64); break;
            case I_VPSRLQ:              encoder::Opcode$< I_VPSRLQ >::Test(list, is64); break;
            case I_VPSRLVD:             encoder::Opcode$< I_VPSRLVD >::Test(list, is64); break;
            case I_VPSRLVQ:             encoder::Opcode$< I_VPSRLVQ >::Test(list, is64); break;
            case I_VPSRLW:              encoder::Opcode$< I_VPSRLW >::Test(list, is64); break;
            case I_VPSUBB:              encoder::Opcode$< I_VPSUBB >::Test(list, is64); break;
            case I_VPSUBD:              encoder::Opcode$< I_VPSUBD >::Test(list, is64); break;
            case I_VPSUBQ:              encoder::Opcode$< I_VPSUBQ >::Test(list, is64); break;
            case I_VPSUBSB:             encoder::Opcode$< I_VPSUBSB >::Test(list, is64); break;
            case I_VPSUBSW:             encoder::Opcode$< I_VPSUBSW >::Test(list, is64); break;
            case I_VPSUBUSB:            encoder::Opcode$< I_VPSUBUSB >::Test(list, is64); break;
            case I_VPSUBUSW:            encoder::Opcode$< I_VPSUBUSW >::Test(list, is64); break;
            case I_VPSUBW:              encoder::Opcode$< I_VPSUBW >::Test(list, is64); break;
            case I_VPTEST:              encoder::Opcode$< I_VPTEST >::Test(list, is64); break;
            case I_VPTESTMD:            encoder::Opcode$< I_VPTESTMD >::Test(list, is64); break;
            case I_VPTESTMQ:            encoder::Opcode$< I_VPTESTMQ >::Test(list, is64); break;
            case I_VPTESTNMD:           encoder::Opcode$< I_VPTESTNMD >::Test(list, is64); break;
            case I_VPTESTNMQ:           encoder::Opcode$< I_VPTESTNMQ >::Test(list, is64); break;
            case I_VPUNPCKHBW:          encoder::Opcode$< I_VPUNPCKHBW >::Test(list, is64); break;
            case I_VPUNPCKHDQ:          encoder::Opcode$< I_VPUNPCKHDQ >::Test(list, is64); break;
            case I_VPUNPCKHQDQ:         encoder::Opcode$< I_VPUNPCKHQDQ >::Test(list, is64); break;
            case I_VPUNPCKHWD:          encoder::Opcode$< I_VPUNPCKHWD >::Test(list, is64); break;
            case I_VPUNPCKLBW:          encoder::Opcode$< I_VPUNPCKLBW >::Test(list, is64); break;
            case I_VPUNPCKLDQ:          encoder::Opcode$< I_VPUNPCKLDQ >::Test(list, is64); break;
            case I_VPUNPCKLQDQ:         encoder::Opcode$< I_VPUNPCKLQDQ >::Test(list, is64); break;
            case I_VPUNPCKLWD:          encoder::Opcode$< I_VPUNPCKLWD >::Test(list, is64); break;
            case I_VPXOR:               encoder::Opcode$< I_VPXOR >::Test(list, is64); break;
            case I_VPXORD:              encoder::Opcode$< I_VPXORD >::Test(list, is64); break;
            case I_VPXORQ:              encoder::Opcode$< I_VPXORQ >::Test(list, is64); break;
            case I_VRCP14PD:            encoder::Opcode$< I_VRCP14PD >::Test(list, is64); break;
            case I_VRCP14PS:            encoder::Opcode$< I_VRCP14PS >::Test(list, is64); break;
            case I_VRCP14SD:            encoder::Opcode$< I_VRCP14SD >::Test(list, is64); break;
            case I_VRCP14SS:            encoder::Opcode$< I_VRCP14SS >::Test(list, is64); break;
            case I_VRCP28PD:            encoder::Opcode$< I_VRCP28PD >::Test(list, is64); break;
            case I_VRCP28PS:            encoder::Opcode$< I_VRCP28PS >::Test(list, is64); break;
            case I_VRCP28SD:            encoder::Opcode$< I_VRCP28SD >::Test(list, is64); break;
            case I_VRCP28SS:            encoder::Opcode$< I_VRCP28SS >::Test(list, is64); break;
            case I_VRCPPS:              encoder::Opcode$< I_VRCPPS >::Test(list, is64); break;
            case I_VRCPSS:              encoder::Opcode$< I_VRCPSS >::Test(list, is64); break;
            case I_VRNDSCALEPD:         encoder::Opcode$< I_VRNDSCALEPD >::Test(list, is64); break;
            case I_VRNDSCALEPS:         encoder::Opcode$< I_VRNDSCALEPS >::Test(list, is64); break;
            case I_VRNDSCALESD:         encoder::Opcode$< I_VRNDSCALESD >::Test(list, is64); break;
            case I_VRNDSCALESS:         encoder::Opcode$< I_VRNDSCALESS >::Test(list, is64); break;
            case I_VROUNDPD:            encoder::Opcode$< I_VROUNDPD >::Test(list, is64); break;
            case I_VROUNDPS:            encoder::Opcode$< I_VROUNDPS >::Test(list, is64); break;
            case I_VROUNDSD:            encoder::Opcode$< I_VROUNDSD >::Test(list, is64); break;
            case I_VROUNDSS:            encoder::Opcode$< I_VROUNDSS >::Test(list, is64); break;
            case I_VRSQRT14PD:          encoder::Opcode$< I_VRSQRT14PD >::Test(list, is64); break;
            case I_VRSQRT14PS:          encoder::Opcode$< I_VRSQRT14PS >::Test(list, is64); break;
            case I_VRSQRT14SD:          encoder::Opcode$< I_VRSQRT14SD >::Test(list, is64); break;
            case I_VRSQRT14SS:          encoder::Opcode$< I_VRSQRT14SS >::Test(list, is64); break;
            case I_VRSQRT28PD:          encoder::Opcode$< I_VRSQRT28PD >::Test(list, is64); break;
            case I_VRSQRT28PS:          encoder::Opcode$< I_VRSQRT28PS >::Test(list, is64); break;
            case I_VRSQRT28SD:          encoder::Opcode$< I_VRSQRT28SD >::Test(list, is64); break;
            case I_VRSQRT28SS:          encoder::Opcode$< I_VRSQRT28SS >::Test(list, is64); break;
            case I_VRSQRTPS:            encoder::Opcode$< I_VRSQRTPS >::Test(list, is64); break;
            case I_VRSQRTSS:            encoder::Opcode$< I_VRSQRTSS >::Test(list, is64); break;
            case I_VSCATTERDPD:         encoder::Opcode$< I_VSCATTERDPD >::Test(list, is64); break;
            case I_VSCATTERDPS:         encoder::Opcode$< I_VSCATTERDPS >::Test(list, is64); break;
            case I_VSCATTERPF0DPD:      encoder::Opcode$< I_VSCATTERPF0DPD >::Test(list, is64); break;
            case I_VSCATTERPF0DPS:      encoder::Opcode$< I_VSCATTERPF0DPS >::Test(list, is64); break;
            case I_VSCATTERPF0QPD:      encoder::Opcode$< I_VSCATTERPF0QPD >::Test(list, is64); break;
            case I_VSCATTERPF0QPS:      encoder::Opcode$< I_VSCATTERPF0QPS >::Test(list, is64); break;
            case I_VSCATTERPF1DPD:      encoder::Opcode$< I_VSCATTERPF1DPD >::Test(list, is64); break;
            case I_VSCATTERPF1DPS:      encoder::Opcode$< I_VSCATTERPF1DPS >::Test(list, is64); break;
            case I_VSCATTERPF1QPD:      encoder::Opcode$< I_VSCATTERPF1QPD >::Test(list, is64); break;
            case I_VSCATTERPF1QPS:      encoder::Opcode$< I_VSCATTERPF1QPS >::Test(list, is64); break;
            case I_VSCATTERQPD:         encoder::Opcode$< I_VSCATTERQPD >::Test(list, is64); break;
            case I_VSCATTERQPS:         encoder::Opcode$< I_VSCATTERQPS >::Test(list, is64); break;
            case I_VSHUFPD:             encoder::Opcode$< I_VSHUFPD >::Test(list, is64); break;
            case I_VSHUFPS:             encoder::Opcode$< I_VSHUFPS >::Test(list, is64); break;
            case I_VSQRTPD:             encoder::Opcode$< I_VSQRTPD >::Test(list, is64); break;
            case I_VSQRTPS:             encoder::Opcode$< I_VSQRTPS >::Test(list, is64); break;
            case I_VSQRTSD:             encoder::Opcode$< I_VSQRTSD >::Test(list, is64); break;
            case I_VSQRTSS:             encoder::Opcode$< I_VSQRTSS >::Test(list, is64); break;
            case I_VSTMXCSR:            encoder::Opcode$< I_VSTMXCSR >::Test(list, is64); break;
            case I_VSUBPD:              encoder::Opcode$< I_VSUBPD >::Test(list, is64); break;
            case I_VSUBPS:              encoder::Opcode$< I_VSUBPS >::Test(list, is64); break;
            case I_VSUBSD:              encoder::Opcode$< I_VSUBSD >::Test(list, is64); break;
            case I_VSUBSS:              encoder::Opcode$< I_VSUBSS >::Test(list, is64); break;
            case I_VTESTPD:             encoder::Opcode$< I_VTESTPD >::Test(list, is64); break;
            case I_VTESTPS:             encoder::Opcode$< I_VTESTPS >::Test(list, is64); break;
            case I_VUCOMISD:            encoder::Opcode$< I_VUCOMISD >::Test(list, is64); break;
            case I_VUCOMISS:            encoder::Opcode$< I_VUCOMISS >::Test(list, is64); break;
            case I_VUNPCKHPD:           encoder::Opcode$< I_VUNPCKHPD >::Test(list, is64); break;
            case I_VUNPCKHPS:           encoder::Opcode$< I_VUNPCKHPS >::Test(list, is64); break;
            case I_VUNPCKLPD:           encoder::Opcode$< I_VUNPCKLPD >::Test(list, is64); break;
            case I_VUNPCKLPS:           encoder::Opcode$< I_VUNPCKLPS >::Test(list, is64); break;
            case I_VXORPD:              encoder::Opcode$< I_VXORPD >::Test(list, is64); break;
            case I_VXORPS:              encoder::Opcode$< I_VXORPS >::Test(list, is64); break;
            case I_VZEROALL:            encoder::Opcode$< I_VZEROALL >::Test(list, is64); break;
            case I_VZEROUPPER:          encoder::Opcode$< I_VZEROUPPER >::Test(list, is64); break;
            case I_WAIT:                encoder::Opcode$< I_WAIT >::Test(list, is64); break;
            case I_WBINVD:              encoder::Opcode$< I_WBINVD >::Test(list, is64); break;
            case I_WRFSBASE:            encoder::Opcode$< I_WRFSBASE >::Test(list, is64); break;
            case I_WRGSBASE:            encoder::Opcode$< I_WRGSBASE >::Test(list, is64); break;
            case I_WRMSR:               encoder::Opcode$< I_WRMSR >::Test(list, is64); break;
            case I_XABORT:              encoder::Opcode$< I_XABORT >::Test(list, is64); break;
            case I_XACQUIRE:            encoder::Opcode$< I_XACQUIRE >::Test(list, is64); break;
            case I_XADD:                encoder::Opcode$< I_XADD >::Test(list, is64); break;
            case I_XBEGIN:              encoder::Opcode$< I_XBEGIN >::Test(list, is64); break;
            case I_XCHG:                encoder::Opcode$< I_XCHG >::Test(list, is64); break;
            case I_XCRYPTCBC:           encoder::Opcode$< I_XCRYPTCBC >::Test(list, is64); break;
            case I_XCRYPTCFB:           encoder::Opcode$< I_XCRYPTCFB >::Test(list, is64); break;
            case I_XCRYPTCTR:           encoder::Opcode$< I_XCRYPTCTR >::Test(list, is64); break;
            case I_XCRYPTECB:           encoder::Opcode$< I_XCRYPTECB >::Test(list, is64); break;
            case I_XCRYPTOFB:           encoder::Opcode$< I_XCRYPTOFB >::Test(list, is64); break;
            case I_XEND:                encoder::Opcode$< I_XEND >::Test(list, is64); break;
            case I_XGETBV:              encoder::Opcode$< I_XGETBV >::Test(list, is64); break;
            case I_XLATB:               encoder::Opcode$< I_XLATB >::Test(list, is64); break;
            case I_XOR:                 encoder::Opcode$< I_XOR >::Test(list, is64); break;
            case I_XORPD:               encoder::Opcode$< I_XORPD >::Test(list, is64); break;
            case I_XORPS:               encoder::Opcode$< I_XORPS >::Test(list, is64); break;
            case I_XRELEASE:            encoder::Opcode$< I_XRELEASE >::Test(list, is64); break;
            case I_XRSTOR:              encoder::Opcode$< I_XRSTOR >::Test(list, is64); break;
            case I_XRSTOR64:            encoder::Opcode$< I_XRSTOR64 >::Test(list, is64); break;
            case I_XSAVE:               encoder::Opcode$< I_XSAVE >::Test(list, is64); break;
            case I_XSAVE64:             encoder::Opcode$< I_XSAVE64 >::Test(list, is64); break;
            case I_XSAVEOPT:            encoder::Opcode$< I_XSAVEOPT >::Test(list, is64); break;
            case I_XSAVEOPT64:          encoder::Opcode$< I_XSAVEOPT64 >::Test(list, is64); break;
            case I_XSETBV:              encoder::Opcode$< I_XSETBV >::Test(list, is64); break;
            case I_XSHA1:               encoder::Opcode$< I_XSHA1 >::Test(list, is64); break;
            case I_XSHA256:             encoder::Opcode$< I_XSHA256 >::Test(list, is64); break;
            case I_XSTORE:              encoder::Opcode$< I_XSTORE >::Test(list, is64); break;
            case I_XTEST:               encoder::Opcode$< I_XTEST >::Test(list, is64); break;
            default:                    break;
            }
        }
#endif
    }
}
