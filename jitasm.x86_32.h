#pragma once
#ifndef jitasm_x86_32_h__
#define jitasm_x86_32_h__
#include "jitasm.x86.h"
namespace jitasm
{
    namespace x86_32
    {
        using namespace x86;

        namespace detail
        {
            using namespace jitasm::detail;
        }

        enum
        {
            NUM_OF_PHYSICAL_REG = 16,
            SIZE_OF_GP_REG = 8
        };

        typedef Reg32		Reg;
        typedef Addr32		Addr;
        typedef Addr32BI	AddrBI;
        typedef Addr32SI	AddrSI;
        typedef Addr32SIB	AddrSIB;

        template<typename OpdN>
        struct AddressingPtr
        {
            // 32bit-Addressing
            Mem$<OpdN> operator[](const Addr32& obj)	{ return Mem$<OpdN>(O_SIZE_32, O_SIZE_32, obj.reg_, RegID::Invalid(), 0, obj.disp_); }
            Mem$<OpdN> operator[](const Addr32BI& obj)	{ return Mem$<OpdN>(O_SIZE_32, O_SIZE_32, obj.base_, obj.index_, 0, obj.disp_); }
            Mem$<OpdN> operator[](const Addr32SI& obj)	{ return Mem$<OpdN>(O_SIZE_32, O_SIZE_32, RegID::Invalid(), obj.index_, obj.scale_, obj.disp_); }
            Mem$<OpdN> operator[](const Addr32SIB& obj)	{ return Mem$<OpdN>(O_SIZE_32, O_SIZE_32, obj.base_, obj.index_, obj.scale_, obj.disp_); }
            VecMem$<OpdN, O_SIZE_128> operator[](const Addr32XmmSIB& obj)	{ return VecMem$<OpdN, O_SIZE_128>(O_SIZE_32, obj.base_, obj.index_, obj.scale_, obj.disp_); }
            VecMem$<OpdN, O_SIZE_256> operator[](const Addr32YmmSIB& obj)	{ return VecMem$<OpdN, O_SIZE_256>(O_SIZE_32, obj.base_, obj.index_, obj.scale_, obj.disp_); }

            Mem$<OpdN> operator[](sint32 disp)			{ return Mem$<OpdN>(O_SIZE_32, O_SIZE_32, RegID::Invalid(), RegID::Invalid(), 0, disp); }
            Mem$<OpdN> operator[](uint32 disp)			{ return Mem$<OpdN>(O_SIZE_32, O_SIZE_32, RegID::Invalid(), RegID::Invalid(), 0, (sint32)disp); }
        };
    }
}
#endif // jitasm_x64_h__