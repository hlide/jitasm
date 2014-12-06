#pragma once
#ifndef jitasm_x86_64_h__
#define jitasm_x86_x64_h__
#include "jitasm.x86.h"
namespace jitasm
{
	namespace x86_64
	{
		using namespace x86;

		namespace detail
		{
			using namespace jitasm::x86::detail;
		}

		enum
		{
			NUM_OF_PHYSICAL_REG = 16,
			SIZE_OF_GP_REG = 8
		};

		typedef Reg64		Reg;
		typedef Addr64		Addr;
		typedef Addr64BI	AddrBI;
		typedef Addr64SI	AddrSI;
		typedef Addr64SIB	AddrSIB;


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

			// 64bit-Addressing
			Mem$<OpdN> operator[](const Addr64& obj)	{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, obj.reg_, RegID::Invalid(), 0, obj.disp_); }
			Mem$<OpdN> operator[](const Addr64BI& obj)	{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, obj.base_, obj.index_, 0, obj.disp_); }
			Mem$<OpdN> operator[](const Addr64SI& obj)	{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, RegID::Invalid(), obj.index_, obj.scale_, obj.disp_); }
			Mem$<OpdN> operator[](const Addr64SIB& obj)	{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, obj.base_, obj.index_, obj.scale_, obj.disp_); }
			//MemOffset64 operator[](sint64 offset)		{ return MemOffset64(offset); }
			//MemOffset64 operator[](uint64 offset)		{ return MemOffset64((sint64)offset); }
			VecMem$<OpdN, O_SIZE_128> operator[](const Addr64XmmSIB& obj)	{ return VecMem$<OpdN, O_SIZE_128>(O_SIZE_64, obj.base_, obj.index_, obj.scale_, obj.disp_); }
			VecMem$<OpdN, O_SIZE_256> operator[](const Addr64YmmSIB& obj)	{ return VecMem$<OpdN, O_SIZE_256>(O_SIZE_64, obj.base_, obj.index_, obj.scale_, obj.disp_); }

            Mem$<OpdN> operator[](sint32 disp)			{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, RegID::Invalid(), RegID::Invalid(), 0, (sint32)disp); }
			Mem$<OpdN> operator[](uint32 disp)			{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, RegID::Invalid(), RegID::Invalid(), 0, (sint32)disp); }
            Mem$<OpdN> operator[](sint64 disp)			{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, RegID::Invalid(), RegID::Invalid(), 0, (sint64)disp); }
            Mem$<OpdN> operator[](uint64 disp)			{ return Mem$<OpdN>(O_SIZE_64, O_SIZE_64, RegID::Invalid(), RegID::Invalid(), 0, (sint64)disp); }
        };
	}
}
#endif // jitasm_x86_64_h__