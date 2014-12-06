#pragma once
#ifndef jitasm_x86_h__
#define jitasm_x86_h__
#include "jitasm.h"
namespace jitasm
{
	namespace x86
	{
		namespace detail
		{
			using namespace jitasm::detail;
		}

		enum PhysicalRegID
		{
			INVALID = 0x0FFFFFFF,
			EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI, R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
			AL = 0, CL, DL, BL, AH, CH, DH, BH, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
			AX = 0, CX, DX, BX, SP, BP, SI, DI, R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
			RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
			ST0 = 0, ST1, ST2, ST3, ST4, ST5, ST6, ST7,
			MM0 = 0, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
			XMM0 = 0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
			YMM0 = 0, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7, YMM8, YMM9, YMM10, YMM11, YMM12, YMM13, YMM14, YMM15,
			EIP = 0,
			RIP = 0,
		};

		enum RegType
		{
			R_TYPE_GP,
			R_TYPE_MMX,
			R_TYPE_XMM,
			R_TYPE_YMM,
			R_TYPE_FPU,
			R_TYPE_IP,
			R_TYPE_SYMBOLIC_GP,
			R_TYPE_SYMBOLIC_MMX,
			R_TYPE_SYMBOLIC_XMM,
			R_TYPE_SYMBOLIC_YMM
		};

		struct RegID
		{
			unsigned type : 4;
			unsigned id   : 28;
			
			bool operator==(RegID const & rhs) const
			{
				return type == rhs.type && id == rhs.id;
			}
			bool operator!=(RegID const & rhs) const
			{
				return !(*this == rhs);
			}
			bool operator<(RegID const & rhs) const
			{
				return type != rhs.type ? type < rhs.type : id < rhs.id;
			}
			
			bool IsInvalid() const
			{
				return type == R_TYPE_GP && id == INVALID;
			}
			
			bool IsSymbolic() const
			{
				return type == R_TYPE_SYMBOLIC_GP || type == R_TYPE_SYMBOLIC_MMX || type == R_TYPE_SYMBOLIC_XMM || type == R_TYPE_SYMBOLIC_YMM;
			}
			
			RegType GetType() const
			{
				return static_cast<RegType>(type);
			}

			static RegID Invalid()
			{
				RegID reg;
				reg.type = R_TYPE_GP;
				reg.id = INVALID;
				return reg;
			}

			static RegID CreatePhysicalRegID(RegType type_, PhysicalRegID id_)
			{
				RegID reg;
				reg.type = type_;
				reg.id = id_;
				return reg;
			}

			static RegID CreateSymbolicRegID(RegType type_)
			{
				static std::atomic_long s_id;
				RegID reg;
				reg.type = type_;
				reg.id = static_cast<unsigned>(++s_id);
				return reg;
			}

			static RegID DuplicateRegID(RegID const & rhs)
			{
				RegID reg;
				reg.type = rhs.type;
				reg.id = rhs.id;
				return reg;
			}
		};

		enum OpdType
		{
			O_TYPE_NONE,
			O_TYPE_REG,
			O_TYPE_MEM,
			O_TYPE_IMM,
			O_TYPE_TYPE_MASK = 0x03,

			O_TYPE_DUMMY = 1 << 2,
			O_TYPE_READ  = 1 << 3,
			O_TYPE_WRITE = 1 << 4
		};

		enum OpdSize
		{
			O_SIZE_8,
			O_SIZE_16,
			O_SIZE_32,
			O_SIZE_64,
			O_SIZE_80,
			O_SIZE_128,
			O_SIZE_224,
			O_SIZE_256,
			O_SIZE_864,
			O_SIZE_4096
		};

		namespace detail
		{
#pragma pack(push, 1)

			struct Opd
			{
				uint8 opdtype_;	// OpdType
				uint8 opdsize_;	// OpdSize

				union
				{
					// REG
					struct
					{
						RegID reg_;
						uint32 reg_assignable_;
					};
					// MEM
					struct
					{
						RegID	base_;
						RegID	index_;
						sint64	scale_;
						sint64	disp_;
						uint8	base_size_ : 4;		// OpdSize
						uint8	index_size_ : 4;	// OpdSize
					};
					// IMM
					sint64 imm_;
				};

				/// NONE
				Opd()
					: opdtype_(O_TYPE_NONE)
				{
				}
				/// REG
				Opd(OpdSize opdsize, RegID const & reg, uint32 reg_assignable = 0xFFFFFFFF)
					: opdtype_(O_TYPE_REG), opdsize_(static_cast< uint8 >(opdsize)), reg_(reg), reg_assignable_(reg_assignable)
				{
				}
				/// MEM
				Opd(OpdSize opdsize, OpdSize base_size, OpdSize index_size, RegID const & base, RegID const & index, sint64 scale, sint64 disp)
					: opdtype_(O_TYPE_MEM), opdsize_(static_cast< uint8 >(opdsize)), base_(base), index_(index), scale_(scale), disp_(disp), base_size_(static_cast<uint8>(base_size)), index_size_(static_cast<uint8>(index_size))
				{
				}
			protected:
				/// IMM
				explicit Opd(OpdSize opdsize, sint64 imm)
					: opdtype_(O_TYPE_IMM), opdsize_(static_cast< uint8 >(opdsize)), imm_(imm)
				{
				}

			public:
				bool	IsNone() const
				{
					return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_NONE;
				}
				bool	IsReg() const
				{
					return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_REG;
                }
				bool	IsGpReg() const
				{
					return IsReg() && (reg_.type == R_TYPE_GP || reg_.type == R_TYPE_SYMBOLIC_GP);
				}
				bool	IsFpuReg() const
				{
					return IsReg() && reg_.type == R_TYPE_FPU;
				}
				bool	IsMmxReg() const
				{
					return IsReg() && (reg_.type == R_TYPE_MMX || reg_.type == R_TYPE_SYMBOLIC_MMX);
				}
				bool	IsXmmReg() const
				{
					return IsReg() && (reg_.type == R_TYPE_XMM || reg_.type == R_TYPE_SYMBOLIC_XMM);
				}
				bool	IsYmmReg() const
				{
					return IsReg() && (reg_.type == R_TYPE_YMM || reg_.type == R_TYPE_SYMBOLIC_YMM);
				}
				bool	IsRip() const
				{
					return IsReg() && reg_.type == R_TYPE_IP;
				}
				bool	IsMem() const
				{
					return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_MEM;
				}
                bool	IsRegOrMem() const
                {
                    return (opdtype_ & (O_TYPE_MEM | O_TYPE_REG)) != 0;
                }
				bool	IsImm() const
				{
					return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_IMM;
				}
				bool	IsDummy() const
				{
					return (opdtype_ & O_TYPE_DUMMY) != 0;
				}
				bool	IsRead() const
				{
					return (opdtype_ & O_TYPE_READ) != 0;
				}
				bool	IsWrite() const
				{
					return (opdtype_ & O_TYPE_WRITE) != 0;
				}

				OpdType GetType() const
				{
					return static_cast< OpdType >(opdtype_);
				}
				OpdSize	GetSize() const
				{
					return static_cast< OpdSize >(opdsize_);
				}
				OpdSize	GetAddressBaseSize() const
				{
					return static_cast< OpdSize >(base_size_);
				}
				OpdSize	GetAddressIndexSize() const
				{
					return static_cast< OpdSize >(index_size_);
				}
				RegID	GetReg() const
				{
					JITASM_ASSERT(IsReg()); return reg_;
				}
				RegID	GetBase() const
				{
					JITASM_ASSERT(IsMem()); return base_;
				}
				RegID	GetIndex() const
				{
					JITASM_ASSERT(IsMem()); return index_;
				}
				sint64	GetScale() const
				{
					JITASM_ASSERT(IsMem()); return scale_;
				}
				sint64	GetDisp() const	
				{
					JITASM_ASSERT(IsMem()); return disp_;
				}
				sint64	GetImm() const
				{
					JITASM_ASSERT(IsImm()); return imm_;
				}

				bool operator==(Opd const & rhs) const
				{
					if ((opdtype_ & O_TYPE_TYPE_MASK) != (rhs.opdtype_ & O_TYPE_TYPE_MASK) || opdsize_ != rhs.opdsize_)
					{
						return false;
					}
					if (IsReg())
					{
						return reg_ == rhs.reg_ && reg_assignable_ == rhs.reg_assignable_;
					}
					if (IsMem())
					{
						return base_ == rhs.base_ && index_ == rhs.index_ && scale_ == rhs.scale_ && disp_ == rhs.disp_ && base_size_ == rhs.base_size_ && index_size_ == rhs.index_size_;
					}
					if (IsImm())
					{
						return imm_ == rhs.imm_;
					}
					return true;
				}
				bool operator!=(Opd const & rhs) const
				{
					return !(*this == rhs);
				}
			};

#pragma pack(pop)

			inline Opd Dummy(Opd const & opd)
			{
				Opd o(opd);
				o.opdtype_ = static_cast<OpdType>(static_cast<int>(o.opdtype_) | O_TYPE_DUMMY);
				return o;
			}

			inline Opd Dummy(Opd const & opd, Opd const & constraint)
			{
				Opd o(opd);
				o.opdtype_ = static_cast<OpdType>(static_cast<int>(o.opdtype_) | O_TYPE_DUMMY);
				o.reg_assignable_ = (1 << constraint.reg_.id);
				return o;
			}

			inline Opd R(Opd const & opd)
			{
				Opd o(opd);
				o.opdtype_ = static_cast<OpdType>(static_cast<int>(o.opdtype_ & O_TYPE_TYPE_MASK) | O_TYPE_READ);
				return o;
			}

			inline Opd W(Opd const & opd)
			{
				Opd o(opd);
				o.opdtype_ = static_cast<OpdType>(static_cast<int>(o.opdtype_ & O_TYPE_TYPE_MASK) | O_TYPE_WRITE);
				return o;
			}

			inline Opd RW(Opd const & opd)
			{
				Opd o(opd);
				o.opdtype_ = static_cast<OpdType>(static_cast<int>(o.opdtype_ & O_TYPE_TYPE_MASK) | O_TYPE_READ | O_TYPE_WRITE);
				return o;
			}

			template< int Size > inline OpdSize ToOpdSize();
			template<> inline OpdSize ToOpdSize< 8 >()
			{
				return O_SIZE_8;
			}
			template<> inline OpdSize ToOpdSize< 16 >()
			{
				return O_SIZE_16;
			}
			template<> inline OpdSize ToOpdSize< 32 >()
			{
				return O_SIZE_32;
			}
			template<> inline OpdSize ToOpdSize< 64 >()
			{
				return O_SIZE_64;
			}
			template<> inline OpdSize ToOpdSize< 80 >()
			{
				return O_SIZE_80;
			}
			template<> inline OpdSize ToOpdSize< 128 >()
			{
				return O_SIZE_128;
			}
			template<> inline OpdSize ToOpdSize< 224 >()
			{
				return O_SIZE_224;
			}
			template<> inline OpdSize ToOpdSize< 256 >() 
			{
				return O_SIZE_256;
			}
			template<> inline OpdSize ToOpdSize< 864 >()
			{
				return O_SIZE_864;
			}
			template<> inline OpdSize ToOpdSize< 4096 >()
			{
				return O_SIZE_4096;
			}

			template< int Size >
			struct Opd$ : Opd
			{
				/// NONE
				Opd$() : Opd()
				{
				}
				/// REG
				explicit Opd$(RegID const & reg, uint32 reg_assignable = 0xFFFFFFFF)
					: Opd(ToOpdSize< Size >(), reg, reg_assignable)
				{
				}
				/// MEM
				Opd$(OpdSize base_size, OpdSize index_size, RegID const & base, RegID const & index, sint64 scale, sint64 disp)
					: Opd(ToOpdSize< Size >(), base_size, index_size, base, index, scale, disp)
				{
				}
			protected:
				/// IMM
				Opd$(sint64 imm)
					: Opd(ToOpdSize< Size >(), imm)
				{
				}
			};

		}	// namespace detail

		typedef detail::Opd$<    8 >	Opd8;
		typedef detail::Opd$<   16 >	Opd16;
		typedef detail::Opd$<   32 >	Opd32;
		typedef detail::Opd$<   64 >	Opd64;
		typedef detail::Opd$<   80 >	Opd80;
		typedef detail::Opd$<  128 >	Opd128;
		typedef detail::Opd$<  224 >	Opd224;
		typedef detail::Opd$<  256 >	Opd256;
		typedef detail::Opd$<  864 >	Opd864;
		typedef detail::Opd$< 4096 >	Opd4096;

		struct Reg8 : Opd8
		{
			Reg8()
				: Opd8(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_GP), 0xFFFFFF0F)
			{
			}
			explicit Reg8(PhysicalRegID id)
				: Opd8(RegID::CreatePhysicalRegID(R_TYPE_GP, id))
			{
			}
		};

		struct Reg16 : Opd16
		{
			Reg16()
				: Opd16(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_GP))
			{
			}
			explicit Reg16(PhysicalRegID id)
				: Opd16(RegID::CreatePhysicalRegID(R_TYPE_GP, id))
			{
			}
			explicit operator Reg8() const
			{
				switch (GetType())
				{
				case R_TYPE_GP:
					return Reg8(PhysicalRegID(GetReg().id <= R8W ? GetReg().id : GetReg().id - R8W + R8B));
				}
				return Reg8();
			}
		};

		struct Reg32 : Opd32
		{
			Reg32()
				: Opd32(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_GP))
			{
			}
			explicit Reg32(PhysicalRegID id)
				: Opd32(RegID::CreatePhysicalRegID(R_TYPE_GP, id))
			{
			}
			explicit operator Reg8() const
			{
				switch (GetType())
				{
				case R_TYPE_GP:
					return Reg8(PhysicalRegID(GetReg().id <= R8 ? GetReg().id : GetReg().id - R8 + R8B));
				}
				return Reg8();
			}
			explicit operator Reg16() const
			{
				switch (GetType())
				{
				case R_TYPE_GP:
					return Reg16(PhysicalRegID(GetReg().id <= R8 ? GetReg().id : GetReg().id - R8 + R8W));
				}
				return Reg16();
			}
		};

		struct Reg64 : Opd64
		{
			Reg64()
				: Opd64(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_GP))
			{
			}
			explicit Reg64(PhysicalRegID id)
				: Opd64(RegID::CreatePhysicalRegID(R_TYPE_GP, id))
			{
			}
			explicit operator Reg8() const
			{
				switch (GetType())
				{
				case R_TYPE_GP:
					return Reg8(PhysicalRegID(GetReg().id <= R8 ? GetReg().id : GetReg().id - R8 + R8B));
				}
				return Reg8();
			}
			explicit operator Reg16() const
			{
				switch (GetType())
				{
				case R_TYPE_GP:
					return Reg16(PhysicalRegID(GetReg().id <= R8 ? GetReg().id : GetReg().id - R8 + R8W));
				}
				return Reg16();
			}
			explicit operator Reg32() const
			{
				switch (GetType())
				{
				case R_TYPE_GP:
					return Reg32(PhysicalRegID(GetReg().id <= R8 ? GetReg().id : GetReg().id - R8 + R8D));
				}
				return Reg32();
			}
		};

		struct Rip64 : Opd64
		{
			Rip64()
				: Opd64(RegID::CreatePhysicalRegID(R_TYPE_IP, RIP))
			{
			}
		};

		struct FpuReg : Opd80
		{
			explicit FpuReg(PhysicalRegID id)
				: Opd80(RegID::CreatePhysicalRegID(R_TYPE_FPU, id))
			{
			}
		};
		
		struct MmxReg : Opd64
		{
			MmxReg()
				: Opd64(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_MMX))
			{
			}
			explicit MmxReg(PhysicalRegID id)
				: Opd64(RegID::CreatePhysicalRegID(R_TYPE_MMX, id))
			{
			}
		};

		struct XmmReg : Opd128
		{
			XmmReg()
				: Opd128(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_XMM))
			{
			}
			explicit XmmReg(PhysicalRegID id)
				: Opd128(RegID::CreatePhysicalRegID(R_TYPE_XMM, id))
			{
			}
		};

		struct YmmReg : Opd256
		{
			YmmReg()
				: Opd256(RegID::CreateSymbolicRegID(R_TYPE_SYMBOLIC_YMM))
			{
			}
			explicit YmmReg(PhysicalRegID id)
				: Opd256(RegID::CreatePhysicalRegID(R_TYPE_YMM, id))
			{
			}
		};

		struct FpuReg_st0 : FpuReg
		{
			FpuReg_st0()
				: FpuReg(ST0)
			{
			}
		};

		template< class OpdN >
		struct Mem$ : OpdN
		{
			Mem$(OpdSize base_size, OpdSize index_size, RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: OpdN(base_size, index_size, base, index, scale, disp)
			{
			}
		};
		typedef Mem$<Opd8>		Mem8;
		typedef Mem$<Opd16>		Mem16;
		typedef Mem$<Opd32>		Mem32;
		typedef Mem$<Opd64>		Mem64;
		typedef Mem$<Opd80>		Mem80;
		typedef Mem$<Opd128>	Mem128;
		typedef Mem$<Opd224>	Mem224;		// FPU environment
		typedef Mem$<Opd256>	Mem256;
		typedef Mem$<Opd864>	Mem864;		// FPU state
		typedef Mem$<Opd4096>	Mem4096;	// FPU, MMX, XMM, MXCSR state

		template< class OpdN, OpdSize IndexSize >
		struct VecMem$ : OpdN
		{
			VecMem$(OpdSize base_size, RegID const & base, RegID const & index, sint64 scale, sint64 disp) : OpdN(base_size, IndexSize, base, index, scale, disp) {}
		};
		typedef VecMem$< Opd32, O_SIZE_128 >	Mem32vxd;
		typedef VecMem$< Opd32, O_SIZE_256 >	Mem32vyd;
		typedef VecMem$< Opd32, O_SIZE_128 >	Mem64vxd;
		typedef VecMem$< Opd32, O_SIZE_256 >	Mem64vyd;
		typedef VecMem$< Opd64, O_SIZE_128 >	Mem32vxq;
		typedef VecMem$< Opd64, O_SIZE_256 >	Mem32vyq;
		typedef VecMem$< Opd64, O_SIZE_128 >	Mem64vxq;
		typedef VecMem$< Opd64, O_SIZE_256 >	Mem64vyq;

		template< class OpdN, class U, class S >
		struct Imm$ : OpdN
		{
			Imm$(U imm) : OpdN((S)imm) {}
		};
		typedef Imm$<Opd8, uint8, sint8>	Imm8;	///< 1 byte immediate
		typedef Imm$<Opd16, uint16, sint16>	Imm16;	///< 2 byte immediate
		typedef Imm$<Opd32, uint32, sint32>	Imm32;	///< 4 byte immediate
		typedef Imm$<Opd64, uint64, sint64>	Imm64;	///< 8 byte immediate

		namespace detail
		{
			inline bool IsInt8(sint64 n)
			{
				return (sint8)n == n;
			}
			inline bool IsInt16(sint64 n)
			{
				return (sint16)n == n;
			}
			inline bool IsInt32(sint64 n)
			{
				return (sint32)n == n;
			}
			inline Opd ImmXor8(const Imm16& imm)
			{
				return IsInt8(imm.GetImm()) ? (Opd)Imm8((sint8)imm.GetImm()) : (Opd)imm;
			}
			inline Opd ImmXor8(const Imm32& imm)
			{
				return IsInt8(imm.GetImm()) ? (Opd)Imm8((sint8)imm.GetImm()) : (Opd)imm;
			}
			inline Opd ImmXor8(const Imm64& imm)
			{
				return IsInt8(imm.GetImm()) ? (Opd)Imm8((sint8)imm.GetImm()) : (Opd)imm;
			}
		}

		struct Addr32
		{
			RegID reg_;
			sint64 disp_;
			Addr32(Reg32 const & obj)
				: reg_(obj.reg_), disp_(0)
			{
			}
			Addr32(RegID const & reg, sint64 disp)
				: reg_(reg), disp_(disp)
			{
			}
		};
		inline Addr32 operator+(Reg32 const & lhs, sint64 rhs)
		{
			return Addr32(lhs.reg_, rhs);
		}
		inline Addr32 operator+(sint64 lhs, Reg32 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32 operator-(Reg32 const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}
		inline Addr32 operator+(Addr32 const & lhs, sint64 rhs)
		{
			return Addr32(lhs.reg_, lhs.disp_ + rhs);
		}
		inline Addr32 operator+(sint64 lhs, Addr32 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32 operator-(Addr32 const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr32BI
		{
			RegID base_;
			RegID index_;
			sint64 disp_;
			Addr32BI(RegID const & base, RegID const & index, sint64 disp)
				: base_(base), index_(index), disp_(disp)
			{
			}
		};
		inline Addr32BI operator+(Addr32 const & lhs, Addr32 const & rhs)
		{
			return Addr32BI(rhs.reg_, lhs.reg_, lhs.disp_ + rhs.disp_);
		}
		inline Addr32BI operator+(Addr32BI const & lhs, sint64 rhs)
		{
			return Addr32BI(lhs.base_, lhs.index_, lhs.disp_ + rhs);
		}
		inline Addr32BI operator+(sint64 lhs, Addr32BI const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32BI operator-(Addr32BI const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr32SI
		{
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr32SI(RegID const & index, sint64 scale, sint64 disp)
				: index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr32SI operator*(Reg32 const & lhs, sint64 rhs)
		{
			return Addr32SI(lhs.reg_, rhs, 0);
		}
		inline Addr32SI operator*(sint64 lhs, Reg32 const & rhs)
		{
			return rhs * lhs;
		}
		inline Addr32SI operator*(Addr32SI const & lhs, sint64 rhs)
		{
			return Addr32SI(lhs.index_, lhs.scale_ * rhs, lhs.disp_);
		}
		inline Addr32SI operator*(sint64 lhs, Addr32SI const & rhs)
		{
			return rhs * lhs;
		}
		inline Addr32SI operator+(Addr32SI const & lhs, sint64 rhs)
		{
			return Addr32SI(lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr32SI operator+(sint64 lhs, Addr32SI const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32SI operator-(Addr32SI const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr32SIB
		{
			RegID base_;
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr32SIB(RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: base_(base), index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr32SIB operator+(Addr32 const & lhs, Addr32SI const & rhs)
		{
			return Addr32SIB(lhs.reg_, rhs.index_, rhs.scale_, lhs.disp_ + rhs.disp_);
		}
		inline Addr32SIB operator+(Addr32SI const & lhs, Addr32 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32SIB operator+(Addr32SIB const & lhs, sint64 rhs)
		{
			return Addr32SIB(lhs.base_, lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr32SIB operator+(sint64 lhs, Addr32SIB const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32SIB operator-(Addr32SIB const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct AddrXmmSI
		{
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			AddrXmmSI(RegID const & index, sint64 scale, sint64 disp)
				: index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline AddrXmmSI operator*(const XmmReg& lhs, sint64 rhs)
		{
			return AddrXmmSI(lhs.reg_, rhs, 0);
		}
		inline AddrXmmSI operator*(sint64 lhs, const XmmReg& rhs)
		{
			return rhs * lhs;
		}
		inline AddrXmmSI operator*(AddrXmmSI const & lhs, sint64 rhs)
		{
			return AddrXmmSI(lhs.index_, lhs.scale_ * rhs, lhs.disp_);
		}
		inline AddrXmmSI operator*(sint64 lhs, AddrXmmSI const & rhs)
		{
			return rhs * lhs;
		}
		inline AddrXmmSI operator+(AddrXmmSI const & lhs, sint64 rhs)
		{
			return AddrXmmSI(lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline AddrXmmSI operator+(sint64 lhs, AddrXmmSI const & rhs)
		{
			return rhs + lhs;
		}
		inline AddrXmmSI operator-(AddrXmmSI const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr32XmmSIB
		{
			RegID base_;
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr32XmmSIB(RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: base_(base), index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr32XmmSIB operator+(Addr32 const & lhs, AddrXmmSI const & rhs)
		{
			return Addr32XmmSIB(lhs.reg_, rhs.index_, rhs.scale_, lhs.disp_ + rhs.disp_);
		}
		inline Addr32XmmSIB operator+(AddrXmmSI const & lhs, Addr32 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32XmmSIB operator+(Addr32XmmSIB const & lhs, sint64 rhs)
		{
			return Addr32XmmSIB(lhs.base_, lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr32XmmSIB operator+(sint64 lhs, Addr32XmmSIB const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32XmmSIB operator-(Addr32XmmSIB const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct AddrYmmSI
		{
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			AddrYmmSI(RegID const & index, sint64 scale, sint64 disp)
				: index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline AddrYmmSI operator*(const YmmReg& lhs, sint64 rhs)
		{
			return AddrYmmSI(lhs.reg_, rhs, 0);
		}
		inline AddrYmmSI operator*(sint64 lhs, const YmmReg& rhs)
		{
			return rhs * lhs;
		}
		inline AddrYmmSI operator*(AddrYmmSI const & lhs, sint64 rhs)
		{
			return AddrYmmSI(lhs.index_, lhs.scale_ * rhs, lhs.disp_);
		}
		inline AddrYmmSI operator*(sint64 lhs, AddrYmmSI const & rhs)
		{
			return rhs * lhs;
		}
		inline AddrYmmSI operator+(AddrYmmSI const & lhs, sint64 rhs)
		{
			return AddrYmmSI(lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline AddrYmmSI operator+(sint64 lhs, AddrYmmSI const & rhs)
		{
			return rhs + lhs;
		}
		inline AddrYmmSI operator-(AddrYmmSI const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr32YmmSIB
		{
			RegID base_;
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr32YmmSIB(RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: base_(base), index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr32YmmSIB operator+(Addr32 const & lhs, AddrYmmSI const & rhs)
		{
			return Addr32YmmSIB(lhs.reg_, rhs.index_, rhs.scale_, lhs.disp_ + rhs.disp_);
		}
		inline Addr32YmmSIB operator+(AddrYmmSI const & lhs, Addr32 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32YmmSIB operator+(Addr32YmmSIB const & lhs, sint64 rhs)
		{
			return Addr32YmmSIB(lhs.base_, lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr32YmmSIB operator+(sint64 lhs, Addr32YmmSIB const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr32YmmSIB operator-(Addr32YmmSIB const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr64
		{
			RegID reg_;
			sint64 disp_;
			Addr64(Reg64 const & obj)
				: reg_(obj.reg_), disp_(0)
			{}	// implicit
			Addr64(RegID const & reg, sint64 disp)
				: reg_(reg), disp_(disp)
			{
			}
		};
		inline Addr64 operator+(Reg64 const & lhs, sint64 rhs)
		{
			return Addr64(lhs.reg_, rhs);
		}
		inline Addr64 operator+(sint64 lhs, Reg64 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64 operator-(Reg64 const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}
		inline Addr64 operator+(Addr64 const & lhs, sint64 rhs)
		{
			return Addr64(lhs.reg_, lhs.disp_ + rhs); }
		inline Addr64 operator+(sint64 lhs, Addr64 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64 operator-(Addr64 const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr64BI
		{
			RegID base_;
			RegID index_;
			sint64 disp_;
			Addr64BI(RegID const & base, RegID const & index, sint64 disp)
				: base_(base), index_(index), disp_(disp)
			{
			}
		};
		inline Addr64BI operator+(Addr64 const & lhs, Addr64 const & rhs)
		{
			return Addr64BI(rhs.reg_, lhs.reg_, lhs.disp_ + rhs.disp_);
		}
		inline Addr64BI operator+(Addr64BI const & lhs, sint64 rhs)
		{
			return Addr64BI(lhs.base_, lhs.index_, lhs.disp_ + rhs);
		}
		inline Addr64BI operator+(sint64 lhs, Addr64BI const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64BI operator-(Addr64BI const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr64SI
		{
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr64SI(RegID const & index, sint64 scale, sint64 disp)
				: index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr64SI operator*(Reg64 const & lhs, sint64 rhs)
		{
			return Addr64SI(lhs.reg_, rhs, 0);
		}
		inline Addr64SI operator*(sint64 lhs, Reg64 const & rhs)
		{
			return rhs * lhs;
		}
		inline Addr64SI operator*(Addr64SI const & lhs, sint64 rhs)
		{
			return Addr64SI(lhs.index_, lhs.scale_ * rhs, lhs.disp_);
		}
		inline Addr64SI operator*(sint64 lhs, Addr64SI const & rhs)
		{
			return rhs * lhs;
		}
		inline Addr64SI operator+(Addr64SI const & lhs, sint64 rhs)
		{
			return Addr64SI(lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr64SI operator+(sint64 lhs, Addr64SI const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64SI operator-(Addr64SI const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr64SIB
		{
			RegID base_;
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr64SIB(RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: base_(base), index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr64SIB operator+(Addr64 const & lhs, Addr64SI const & rhs)
		{
			return Addr64SIB(lhs.reg_, rhs.index_, rhs.scale_, lhs.disp_ + rhs.disp_);
		}
		inline Addr64SIB operator+(Addr64SI const & lhs, Addr64 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64SIB operator+(Addr64SIB const & lhs, sint64 rhs)
		{
			return Addr64SIB(lhs.base_, lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr64SIB operator+(sint64 lhs, Addr64SIB const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64SIB operator-(Addr64SIB const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr64XmmSIB
		{
			RegID base_;
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr64XmmSIB(RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: base_(base), index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr64XmmSIB operator+(Addr64 const & lhs, AddrXmmSI const & rhs)
		{
			return Addr64XmmSIB(lhs.reg_, rhs.index_, rhs.scale_, lhs.disp_ + rhs.disp_);
		}
		inline Addr64XmmSIB operator+(AddrXmmSI const & lhs, Addr64 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64XmmSIB operator+(Addr64XmmSIB const & lhs, sint64 rhs)
		{
			return Addr64XmmSIB(lhs.base_, lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr64XmmSIB operator+(sint64 lhs, Addr64XmmSIB const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64XmmSIB operator-(Addr64XmmSIB const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		struct Addr64YmmSIB
		{
			RegID base_;
			RegID index_;
			sint64 scale_;
			sint64 disp_;
			Addr64YmmSIB(RegID const & base, RegID const & index, sint64 scale, sint64 disp)
				: base_(base), index_(index), scale_(scale), disp_(disp)
			{
			}
		};
		inline Addr64YmmSIB operator+(Addr64 const & lhs, AddrYmmSI const & rhs)
		{
			return Addr64YmmSIB(lhs.reg_, rhs.index_, rhs.scale_, lhs.disp_ + rhs.disp_);
		}
		inline Addr64YmmSIB operator+(AddrYmmSI const & lhs, Addr64 const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64YmmSIB operator+(Addr64YmmSIB const & lhs, sint64 rhs)
		{
			return Addr64YmmSIB(lhs.base_, lhs.index_, lhs.scale_, lhs.disp_ + rhs);
		}
		inline Addr64YmmSIB operator+(sint64 lhs, Addr64YmmSIB const & rhs)
		{
			return rhs + lhs;
		}
		inline Addr64YmmSIB operator-(Addr64YmmSIB const & lhs, sint64 rhs)
		{
			return lhs + -rhs;
		}

		enum InstrID
		{
			I_ADC, I_ADD, I_AND,
			I_BSF, I_BSR, I_BSWAP, I_BT, I_BTC, I_BTR, I_BTS,
			I_CALL, I_CBW, I_CWDE, I_CDQE, I_CLC, I_CLD, I_CLI, I_CLTS, I_CMC, I_CMOVCC, I_CMP, I_CMPS_B, I_CMPS_W, I_CMPS_D, I_CMPS_Q, I_CMPXCHG,
			I_CMPXCHG8B, I_CMPXCHG16B, I_CPUID, I_CWD, I_CDQ, I_CQO,
			I_DEC, I_DIV,
			I_ENTER,
			I_HLT,
			I_IDIV, I_IMUL, I_IN, I_INC, I_INS_B, I_INS_W, I_INS_D, I_INVD, I_INVLPG, I_INT3, I_INTN, I_INTO, I_IRET, I_IRETD, I_IRETQ,
			I_JMP, I_JCC,
            I_LAR, I_LEA, I_LEAVE, I_LLDT, I_LMSW, I_LSL, I_LTR, I_LODS_B, I_LODS_W, I_LODS_D, I_LODS_Q, I_LOOPCC,
			I_MOV, I_MOVBE, I_MOVS_B, I_MOVS_W, I_MOVS_D, I_MOVS_Q, I_MOVZX, I_MOVSX, I_MOVSXD, I_MUL,
			I_NEG, I_NOP, I_NOT,
			I_OR, I_OUT, I_OUTS_B, I_OUTS_W, I_OUTS_D,
			I_POP, I_POPAD, I_POPF, I_POPFD, I_POPFQ, I_PUSH, I_PUSHAD, I_PUSHF, I_PUSHFD, I_PUSHFQ,
			I_RDMSR, I_RDPMC, I_RDTSC, I_RET, I_RCL, I_RCR, I_ROL, I_ROR, I_RSM,
			I_SAR, I_SHL, I_SHR, I_SBB, I_SCAS_B, I_SCAS_W, I_SCAS_D, I_SCAS_Q, I_SETCC, I_SHLD, I_SHRD, I_SGDT, I_SIDT, I_SLDT, I_SMSW, I_STC, I_STD, I_STI,
			I_STOS_B, I_STOS_W, I_STOS_D, I_STOS_Q, I_SUB, I_SWAPGS, I_SYSCALL, I_SYSENTER, I_SYSEXIT, I_SYSRET,
			I_TEST,
			I_UD2,
			I_VERR, I_VERW,
			I_WAIT, I_WBINVD, I_WRMSR,
			I_XADD, I_XCHG, I_XGETBV, I_XLATB, I_XOR,

			I_F2XM1, I_FABS, I_FADD, I_FADDP, I_FIADD,
			I_FBLD, I_FBSTP, I_FCHS, I_FCLEX, I_FNCLEX, I_FCMOVCC, I_FCOM, I_FCOMP, I_FCOMPP, I_FCOMI, I_FCOMIP, I_FCOS,
			I_FDECSTP, I_FDIV, I_FDIVP, I_FIDIV, I_FDIVR, I_FDIVRP, I_FIDIVR,
			I_FFREE,
			I_FICOM, I_FICOMP, I_FILD, I_FINCSTP, I_FINIT, I_FNINIT, I_FIST, I_FISTP,
			I_FLD, I_FLD1, I_FLDCW, I_FLDENV, I_FLDL2E, I_FLDL2T, I_FLDLG2, I_FLDLN2, I_FLDPI, I_FLDZ,
			I_FMUL, I_FMULP, I_FIMUL,
			I_FNOP,
			I_FPATAN, I_FPREM, I_FPREM1, I_FPTAN,
			I_FRNDINT, I_FRSTOR,
			I_FSAVE, I_FNSAVE, I_FSCALE, I_FSIN, I_FSINCOS, I_FSQRT, I_FST, I_FSTP, I_FSTCW, I_FNSTCW, I_FSTENV, I_FNSTENV, I_FSTSW, I_FNSTSW,
			I_FSUB, I_FSUBP, I_FISUB, I_FSUBR, I_FSUBRP, I_FISUBR,
			I_FTST,
			I_FUCOM, I_FUCOMP, I_FUCOMPP, I_FUCOMI, I_FUCOMIP,
			I_FXAM, I_FXCH, I_FXRSTOR, I_FXSAVE, I_FXTRACT,
			I_FYL2X, I_FYL2XP1,

			I_ADDPS, I_ADDSS, I_ADDPD, I_ADDSD, I_ADDSUBPS, I_ADDSUBPD, I_ANDPS, I_ANDPD, I_ANDNPS, I_ANDNPD,
			I_BLENDPS, I_BLENDPD, I_BLENDVPS, I_BLENDVPD,
			I_CLFLUSH, I_CMPPS, I_CMPSS, I_CMPPD, I_CMPSD, I_COMISS, I_COMISD, I_CRC32,
			I_CVTDQ2PD, I_CVTDQ2PS, I_CVTPD2DQ, I_CVTPD2PI, I_CVTPD2PS, I_CVTPI2PD, I_CVTPI2PS, I_CVTPS2DQ, I_CVTPS2PD, I_CVTPS2PI, I_CVTSD2SI,
			I_CVTSD2SS, I_CVTSI2SD, I_CVTSI2SS, I_CVTSS2SD, I_CVTSS2SI, I_CVTTPD2DQ, I_CVTTPD2PI, I_CVTTPS2DQ, I_CVTTPS2PI, I_CVTTSD2SI, I_CVTTSS2SI,
			I_DIVPS, I_DIVSS, I_DIVPD, I_DIVSD, I_DPPS, I_DPPD,
			I_EMMS, I_EXTRACTPS,
			I_FISTTP,
			I_HADDPS, I_HADDPD, I_HSUBPS, I_HSUBPD,
			I_INSERTPS,
			I_LDDQU, I_LDMXCSR, I_LFENCE,
			I_MASKMOVDQU, I_MASKMOVQ, I_MAXPS, I_MAXSS, I_MAXPD, I_MAXSD, I_MFENCE, I_MINPS, I_MINSS, I_MINPD, I_MINSD, I_MONITOR,
			I_MOVAPD, I_MOVAPS, I_MOVD, I_MOVDDUP, I_MOVDQA, I_MOVDQU, I_MOVDQ2Q, I_MOVHLPS, I_MOVLHPS, I_MOVHPS, I_MOVHPD, I_MOVLPS, I_MOVLPD,
			I_MOVMSKPS, I_MOVMSKPD, I_MOVNTDQ, I_MOVNTDQA, I_MOVNTI, I_MOVNTPD, I_MOVNTPS, I_MOVNTQ, I_MOVQ, I_MOVQ2DQ, I_MOVSD, I_MOVSS,
			I_MOVSHDUP, I_MOVSLDUP, I_MOVUPS, I_MOVUPD, I_MPSADBW, I_MULPS, I_MULSS, I_MULPD, I_MULSD, I_MWAIT,
			I_ORPS, I_ORPD,
			I_PABSB, I_PABSD, I_PABSW, I_PACKSSDW, I_PACKSSWB, I_PACKUSDW, I_PACKUSWB, I_PADDB, I_PADDD, I_PADDQ, I_PADDSB, I_PADDSW, I_PADDUSB,
			I_PADDUSW, I_PADDW, I_PALIGNR, I_PAND, I_PANDN, I_PAUSE, I_PAVGB, I_PAVGW,
			I_PBLENDVB, I_PBLENDW,
			I_PCMPEQB, I_PCMPEQW, I_PCMPEQD, I_PCMPEQQ, I_PCMPESTRI, I_PCMPESTRM, I_PCMPISTRI, I_PCMPISTRM, I_PCMPGTB, I_PCMPGTW, I_PCMPGTD, I_PCMPGTQ,
			I_PEXTRB, I_PEXTRW, I_PEXTRD, I_PEXTRQ,
			I_PHADDW, I_PHADDD, I_PHADDSW, I_PHMINPOSUW, I_PHSUBW, I_PHSUBD, I_PHSUBSW,
			I_PINSRB, I_PINSRW, I_PINSRD, I_PINSRQ,
			I_PMADDUBSW, I_PMADDWD, I_PMAXSB, I_PMAXSW, I_PMAXSD, I_PMAXUB, I_PMAXUW, I_PMAXUD, I_PMINSB, I_PMINSW, I_PMINSD, I_PMINUB, I_PMINUW,
			I_PMINUD, I_PMOVMSKB, I_PMOVSXBW, I_PMOVSXBD, I_PMOVSXBQ, I_PMOVSXWD, I_PMOVSXWQ, I_PMOVSXDQ, I_PMOVZXBW, I_PMOVZXBD, I_PMOVZXBQ, I_PMOVZXWD,
			I_PMOVZXWQ, I_PMOVZXDQ, I_PMULDQ, I_PMULHRSW, I_PMULHUW, I_PMULHW, I_PMULLW, I_PMULLD, I_PMULUDQ,
			I_POPCNT, I_POR,
			I_PREFETCH,
			I_PSADBW, I_PSHUFB, I_PSHUFD, I_PSHUFHW, I_PSHUFLW, I_PSHUFW, I_PSIGNB, I_PSIGNW, I_PSIGND, I_PSLLW, I_PSLLD, I_PSLLQ, I_PSLLDQ, I_PSRAW,
			I_PSRAD, I_PSRLW, I_PSRLD, I_PSRLQ, I_PSRLDQ, I_PSUBB, I_PSUBW, I_PSUBD, I_PSUBQ, I_PSUBSB, I_PSUBSW, I_PSUBUSB, I_PSUBUSW,
			I_PTEST,
			I_PUNPCKHBW, I_PUNPCKHWD, I_PUNPCKHDQ, I_PUNPCKHQDQ, I_PUNPCKLBW, I_PUNPCKLWD, I_PUNPCKLDQ, I_PUNPCKLQDQ,
			I_PXOR,
			I_RCPPS, I_RCPSS, I_ROUNDPS, I_ROUNDPD, I_ROUNDSS, I_ROUNDSD, I_RSQRTPS, I_RSQRTSS,
			I_SFENCE, I_SHUFPS, I_SHUFPD, I_SQRTPS, I_SQRTSS, I_SQRTPD, I_SQRTSD, I_STMXCSR, I_SUBPS, I_SUBSS, I_SUBPD, I_SUBSD,
			I_UCOMISS, I_UCOMISD, I_UNPCKHPS, I_UNPCKHPD, I_UNPCKLPS, I_UNPCKLPD,
			I_XORPS, I_XORPD,

			I_VBROADCASTSS, I_VBROADCASTSD, I_VBROADCASTF128,
			I_VEXTRACTF128,
			I_VINSERTF128,
			I_VMASKMOVPS, I_VMASKMOVPD,
			I_VPERMILPD, I_VPERMILPS, I_VPERM2F128,
			I_VTESTPS, I_VTESTPD,
			I_VZEROALL, I_VZEROUPPER,

			I_AESENC, I_AESENCLAST, I_AESDEC, I_AESDECLAST, I_AESIMC, I_AESKEYGENASSIST,
			I_PCLMULQDQ,

			// FMA
			I_VFMADD132PD, I_VFMADD213PD, I_VFMADD231PD, I_VFMADD132PS, I_VFMADD213PS, I_VFMADD231PS,
			I_VFMADD132SD, I_VFMADD213SD, I_VFMADD231SD, I_VFMADD132SS, I_VFMADD213SS, I_VFMADD231SS,
			I_VFMADDSUB132PD, I_VFMADDSUB213PD, I_VFMADDSUB231PD, I_VFMADDSUB132PS, I_VFMADDSUB213PS, I_VFMADDSUB231PS,
			I_VFMSUBADD132PD, I_VFMSUBADD213PD, I_VFMSUBADD231PD, I_VFMSUBADD132PS, I_VFMSUBADD213PS, I_VFMSUBADD231PS,
			I_VFMSUB132PD, I_VFMSUB213PD, I_VFMSUB231PD, I_VFMSUB132PS, I_VFMSUB213PS, I_VFMSUB231PS,
			I_VFMSUB132SD, I_VFMSUB213SD, I_VFMSUB231SD, I_VFMSUB132SS, I_VFMSUB213SS, I_VFMSUB231SS,
			I_VFNMADD132PD, I_VFNMADD213PD, I_VFNMADD231PD, I_VFNMADD132PS, I_VFNMADD213PS, I_VFNMADD231PS,
			I_VFNMADD132SD, I_VFNMADD213SD, I_VFNMADD231SD, I_VFNMADD132SS, I_VFNMADD213SS, I_VFNMADD231SS,
			I_VFNMSUB132PD, I_VFNMSUB213PD, I_VFNMSUB231PD, I_VFNMSUB132PS, I_VFNMSUB213PS, I_VFNMSUB231PS,
			I_VFNMSUB132SD, I_VFNMSUB213SD, I_VFNMSUB231SD, I_VFNMSUB132SS, I_VFNMSUB213SS, I_VFNMSUB231SS,

			// F16C
			I_RDFSBASE, I_RDGSBASE, I_RDRAND, I_WRFSBASE, I_WRGSBASE, I_VCVTPH2PS, I_VCVTPS2PH,

			// BMI
			I_ANDN, I_BEXTR, I_BLSI, I_BLSMSK, I_BLSR, I_BZHI, I_LZCNT, I_MULX, I_PDEP, I_PEXT, I_RORX, I_SARX, I_SHLX, I_SHRX, I_TZCNT, I_INVPCID,

			// XOP
			I_VFRCZPD, I_VFRCZPS, I_VFRCZSD, I_VFRCZSS,
			I_VPCMOV, I_VPCOMB, I_VPCOMD, I_VPCOMQ, I_VPCOMUB, I_VPCOMUD, I_VPCOMUQ, I_VPCOMUW, I_VPCOMW, I_VPERMIL2PD, I_VPERMIL2PS,
			I_VPHADDBD, I_VPHADDBQ, I_VPHADDBW, I_VPHADDDQ, I_VPHADDUBD, I_VPHADDUBQ, I_VPHADDUBW, I_VPHADDUDQ, I_VPHADDUWD, I_VPHADDUWQ,
			I_VPHADDWD, I_VPHADDWQ, I_VPHSUBBW, I_VPHSUBDQ, I_VPHSUBWD,
			I_VPMACSDD, I_VPMACSDQH, I_VPMACSDQL, I_VPMACSSDD, I_VPMACSSDQH, I_VPMACSSDQL, I_VPMACSSWD, I_VPMACSSWW, I_VPMACSWD, I_VPMACSWW,
			I_VPMADCSSWD, I_VPMADCSWD,
			I_VPPERM, I_VPROTB, I_VPROTD, I_VPROTQ, I_VPROTW, I_VPSHAB, I_VPSHAD, I_VPSHAQ, I_VPSHAW, I_VPSHLB, I_VPSHLD, I_VPSHLQ, I_VPSHLW,

			// FMA4
			I_VFMADDPD, I_VFMADDPS, I_VFMADDSD, I_VFMADDSS,
			I_VFMADDSUBPD, I_VFMADDSUBPS,
			I_VFMSUBADDPD, I_VFMSUBADDPS,
			I_VFMSUBPD, I_VFMSUBPS, I_VFMSUBSD, I_VFMSUBSS,
			I_VFNMADDPD, I_VFNMADDPS, I_VFNMADDSD, I_VFNMADDSS,
			I_VFNMSUBPD, I_VFNMSUBPS, I_VFNMSUBSD, I_VFNMSUBSS,

			// AVX2
			I_VBROADCASTI128, I_VPBROADCASTB, I_VPBROADCASTW, I_VPBROADCASTD, I_VPBROADCASTQ,
			I_PBLENDD, I_VPERMD, I_VPERMQ, I_VPERMPS, I_VPERMPD, I_VPERM2I128,
			I_VEXTRACTI128, I_VINSERTI128, I_VMASKMOVD, I_VMASKMOVQ, I_VPSLLVD, I_VPSLLVQ, I_VPSRAVD, I_VPSRLVD, I_VPSRLVQ,
			I_VGATHERDPS, I_VGATHERQPS, I_VGATHERDPD, I_VGATHERQPD, I_VPGATHERDD, I_VPGATHERQD, I_VPGATHERDQ, I_VPGATHERQQ,

			// jitasm compiler instructions
			I_COMPILER_DECLARE_REG_ARG,		///< Declare register argument
			I_COMPILER_DECLARE_STACK_ARG,	///< Declare stack argument
			I_COMPILER_DECLARE_RESULT_REG,	///< Declare result register (eax/rax/xmm0)
			I_COMPILER_PROLOG,				///< Function prolog
			I_COMPILER_EPILOG,				///< Function epilog

			I_ALIGN,
			I_NULL,
			I_SOURCE,

			// constants pool 
			I_DB,
			I_DW,
			I_DD,
			I_DQ,
		};

		enum JumpCondition
		{
			JCC_O, JCC_NO, JCC_B, JCC_AE, JCC_E, JCC_NE, JCC_BE, JCC_A, JCC_S, JCC_NS, JCC_P, JCC_NP, JCC_L, JCC_GE, JCC_LE, JCC_G,
			JCC_CXZ, JCC_ECXZ, JCC_RCXZ,
		};

        enum LoopCondition
        {
            LOOP_NE, LOOP_E, LOOP_NC,
        };

		enum EncodingFlags
		{
			E_SPECIAL = 1 << 0,
			E_OPERAND_SIZE_PREFIX = 1 << 1,	///< Operand-size override prefix
			E_REP_PREFIX = 1 << 2,	///< REP prefix
			E_REXW_PREFIX = 1 << 3,	///< REX.W
			E_MANDATORY_PREFIX_66 = 1 << 4,	///< Mandatory prefix 66
			E_MANDATORY_PREFIX_F2 = 1 << 5,	///< Mandatory prefix F2
			E_MANDATORY_PREFIX_F3 = 1 << 6,	///< Mandatory prefix F3
			E_VEX = 1 << 7,
			E_XOP = 1 << 8,
			E_VEX_L = 1 << 9,
			E_VEX_W = 1 << 10,
			E_VEX_MMMMM_SHIFT = 11,
			E_VEX_MMMMM_MASK = 0x1F << E_VEX_MMMMM_SHIFT,
			E_VEX_0F = 1 << E_VEX_MMMMM_SHIFT,
			E_VEX_0F38 = 2 << E_VEX_MMMMM_SHIFT,
			E_VEX_0F3A = 3 << E_VEX_MMMMM_SHIFT,
			E_XOP_M00011 = 3 << E_VEX_MMMMM_SHIFT,
			E_XOP_M01000 = 8 << E_VEX_MMMMM_SHIFT,
			E_XOP_M01001 = 9 << E_VEX_MMMMM_SHIFT,
			E_VEX_PP_SHIFT = 16,
			E_VEX_PP_MASK = 0x3 << E_VEX_PP_SHIFT,
			E_VEX_66 = 1 << E_VEX_PP_SHIFT,
			E_VEX_F3 = 2 << E_VEX_PP_SHIFT,
			E_VEX_F2 = 3 << E_VEX_PP_SHIFT,
			E_XOP_P00 = 0 << E_VEX_PP_SHIFT,
			E_XOP_P01 = 1 << E_VEX_PP_SHIFT,

			E_VEX_128 = E_VEX,
			E_VEX_256 = E_VEX | E_VEX_L,
			E_VEX_LIG = E_VEX,
			E_VEX_LZ = E_VEX,
			E_VEX_66_0F = E_VEX_66 | E_VEX_0F,
			E_VEX_66_0F38 = E_VEX_66 | E_VEX_0F38,
			E_VEX_66_0F3A = E_VEX_66 | E_VEX_0F3A,
			E_VEX_F2_0F = E_VEX_F2 | E_VEX_0F,
			E_VEX_F2_0F38 = E_VEX_F2 | E_VEX_0F38,
			E_VEX_F2_0F3A = E_VEX_F2 | E_VEX_0F3A,
			E_VEX_F3_0F = E_VEX_F3 | E_VEX_0F,
			E_VEX_F3_0F38 = E_VEX_F3 | E_VEX_0F38,
			E_VEX_F3_0F3A = E_VEX_F3 | E_VEX_0F3A,
			E_VEX_W0 = 0,
			E_VEX_W1 = E_VEX_W,
			E_VEX_WIG = 0,
			E_XOP_128 = E_XOP,
			E_XOP_256 = E_XOP | E_VEX_L,
			E_XOP_W0 = 0,
			E_XOP_W1 = E_VEX_W,

			E_NO_BREAK = 1 << 30,
			E_ENCODED = 1 << 31,

			// Aliases
			E_VEX_128_0F_WIG = E_VEX_128 | E_VEX_0F | E_VEX_WIG,
			E_VEX_256_0F_WIG = E_VEX_256 | E_VEX_0F | E_VEX_WIG,
			E_VEX_128_66_0F_WIG = E_VEX_128 | E_VEX_66_0F | E_VEX_WIG,
			E_VEX_256_66_0F_WIG = E_VEX_256 | E_VEX_66_0F | E_VEX_WIG,
			E_VEX_128_66_0F38_WIG = E_VEX_128 | E_VEX_66_0F38 | E_VEX_WIG,
			E_VEX_256_66_0F38_WIG = E_VEX_256 | E_VEX_66_0F38 | E_VEX_WIG,
			E_VEX_128_66_0F38_W0 = E_VEX_128 | E_VEX_66_0F38 | E_VEX_W0,
			E_VEX_256_66_0F38_W0 = E_VEX_256 | E_VEX_66_0F38 | E_VEX_W0,
			E_VEX_128_66_0F38_W1 = E_VEX_128 | E_VEX_66_0F38 | E_VEX_W1,
			E_VEX_256_66_0F38_W1 = E_VEX_256 | E_VEX_66_0F38 | E_VEX_W1,
			E_VEX_128_66_0F3A_W0 = E_VEX_128 | E_VEX_66_0F3A | E_VEX_W0,
			E_VEX_256_66_0F3A_W0 = E_VEX_256 | E_VEX_66_0F3A | E_VEX_W0,
		};

		struct Instr
		{
			static size_t const MAX_OPERAND_COUNT = 6;

			InstrID	    id_;
			uint32      opcode_;
			uint32      encoding_flag_;
			detail::Opd	opd_[MAX_OPERAND_COUNT];
			
			Instr(
				InstrID             id,
				detail::Opd const & opd1 = detail::Opd(),
				detail::Opd const & opd2 = detail::Opd(),
				detail::Opd const & opd3 = detail::Opd(),
				detail::Opd const & opd4 = detail::Opd(),
				detail::Opd const & opd5 = detail::Opd(),
				detail::Opd const & opd6 = detail::Opd())
				: id_(id), opcode_(0), encoding_flag_(0)
			{
				opd_[0] = opd1, opd_[1] = opd2, opd_[2] = opd3, opd_[3] = opd4, opd_[4] = opd5, opd_[5] = opd6;
			}

			Instr(
				InstrID             id,
				uint32              opcode,
				uint32              encoding_flag,
				detail::Opd const & opd1 = detail::Opd(),
				detail::Opd const & opd2 = detail::Opd(),
				detail::Opd const & opd3 = detail::Opd(),
				detail::Opd const & opd4 = detail::Opd(),
				detail::Opd const & opd5 = detail::Opd(),
				detail::Opd const & opd6 = detail::Opd())
				: id_(id), opcode_(opcode), encoding_flag_(encoding_flag | E_ENCODED)
			{
				opd_[0] = opd1, opd_[1] = opd2, opd_[2] = opd3, opd_[3] = opd4, opd_[4] = opd5, opd_[5] = opd6;
			}

			InstrID GetID() const
			{
				return id_;
			}
			detail::Opd const & GetOpd(size_t index) const
			{
				return opd_[index];
			}
			detail::Opd & GetOpd(size_t index)
			{
				return opd_[index];
			}
		};
	}
}
#endif // jitasm_x86_h__