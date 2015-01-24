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
            INVALID = 0x03FFFFFF,
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

            R_TYPE_SYMBOLIC_MASK = 0x40,
            R_TYPE_SYMBOLIC_GP = R_TYPE_GP | R_TYPE_SYMBOLIC_MASK,
            R_TYPE_SYMBOLIC_MMX = R_TYPE_MMX | R_TYPE_SYMBOLIC_MASK,
            R_TYPE_SYMBOLIC_XMM = R_TYPE_XMM | R_TYPE_SYMBOLIC_MASK,
            R_TYPE_SYMBOLIC_YMM = R_TYPE_YMM | R_TYPE_SYMBOLIC_MASK,

            R_TYPE_MAPPED_MASK = 0x80,
            R_TYPE_MAPPED_GP = R_TYPE_GP | R_TYPE_MAPPED_MASK,
            R_TYPE_MAPPED_MMX = R_TYPE_MMX | R_TYPE_MAPPED_MASK,
            R_TYPE_MAPPED_XMM = R_TYPE_XMM | R_TYPE_MAPPED_MASK,
            R_TYPE_MAPPED_YMM = R_TYPE_YMM | R_TYPE_MAPPED_MASK,
        };

        struct RegID
        {
            unsigned type : 8;
            unsigned id   : 26;
            
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
                return (type & R_TYPE_SYMBOLIC_MASK) == R_TYPE_SYMBOLIC_MASK;
            }
            
            bool IsMapped() const
            {
                return (type & R_TYPE_MAPPED_MASK) == R_TYPE_MAPPED_MASK;
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
                uint8 opdtype_; // OpdType
                uint8 opdsize_; // OpdSize

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
                        RegID   base_;
                        RegID   index_;
                        sint64  scale_;
                        sint64  disp_;
                        uint8   base_size_ : 4;     // OpdSize
                        uint8   index_size_ : 4;    // OpdSize
                    };
                    // IMM
                    sint64 imm_;
                };

                /// NONE
                Opd()
                    : opdtype_(O_TYPE_NONE), opdsize_(0)
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
                bool    IsNone() const
                {
                    return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_NONE;
                }
                bool    IsReg() const
                {
                    return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_REG;
                }
                bool    IsGpReg() const
                {
                    return IsReg() && ((reg_.type & ~(R_TYPE_SYMBOLIC_MASK | R_TYPE_MAPPED_MASK)) == R_TYPE_GP);
                }
                bool    IsFpuReg() const
                {
                    return IsReg() && reg_.type == R_TYPE_FPU;
                }
                bool    IsMmxReg() const
                {
                    return IsReg() && ((reg_.type & ~(R_TYPE_SYMBOLIC_MASK | R_TYPE_MAPPED_MASK)) == R_TYPE_MMX);
                }
                bool    IsXmmReg() const
                {
                    return IsReg() && ((reg_.type & ~(R_TYPE_SYMBOLIC_MASK | R_TYPE_MAPPED_MASK)) == R_TYPE_XMM);
                }
                bool    IsYmmReg() const
                {
                    return IsReg() && ((reg_.type & ~(R_TYPE_SYMBOLIC_MASK | R_TYPE_MAPPED_MASK)) == R_TYPE_YMM);
                }
                bool    IsRip() const
                {
                    return IsReg() && reg_.type == R_TYPE_IP;
                }
                bool    IsMem() const
                {
                    return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_MEM;
                }
                bool    IsRegOrMem() const
                {
                    return (opdtype_ & (O_TYPE_MEM | O_TYPE_REG)) != 0;
                }
                bool    IsImm() const
                {
                    return (opdtype_ & O_TYPE_TYPE_MASK) == O_TYPE_IMM;
                }
                bool    IsDummy() const
                {
                    return (opdtype_ & O_TYPE_DUMMY) != 0;
                }
                bool    IsRead() const
                {
                    return (opdtype_ & O_TYPE_READ) != 0;
                }
                bool    IsWrite() const
                {
                    return (opdtype_ & O_TYPE_WRITE) != 0;
                }

                OpdType GetType() const
                {
                    return static_cast< OpdType >(opdtype_);
                }
                OpdSize GetSize() const
                {
                    return static_cast< OpdSize >(opdsize_);
                }
                OpdSize GetAddressBaseSize() const
                {
                    return static_cast< OpdSize >(base_size_);
                }
                OpdSize GetAddressIndexSize() const
                {
                    return static_cast< OpdSize >(index_size_);
                }
                RegID   GetReg() const
                {
                    return reg_;
                }
                RegID   GetBase() const
                {
                    return base_;
                }
                RegID   GetIndex() const
                {
                    return index_;
                }
                sint64  GetScale() const
                {
                    return scale_;
                }
                sint64  GetDisp() const 
                {
                    return disp_;
                }
                sint64  GetImm() const
                {
                    return imm_;
                }

                bool operator==(Opd const & rhs) const
                {
                    uint8 type = (opdtype_ & O_TYPE_TYPE_MASK);
                    if (type != (rhs.opdtype_ & O_TYPE_TYPE_MASK) || opdsize_ != rhs.opdsize_)
                    {
                        return false;
                    }
                    switch (type)
                    {
                    case O_TYPE_REG:
                        return reg_ == rhs.reg_ && reg_assignable_ == rhs.reg_assignable_;
                    case O_TYPE_MEM: 
                        return base_ == rhs.base_ && index_ == rhs.index_ && scale_ == rhs.scale_ && disp_ == rhs.disp_ && base_size_ == rhs.base_size_ && index_size_ == rhs.index_size_;
                    case O_TYPE_IMM:
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

        }   // namespace detail

        typedef detail::Opd$<    8 >    Opd8;
        typedef detail::Opd$<   16 >    Opd16;
        typedef detail::Opd$<   32 >    Opd32;
        typedef detail::Opd$<   64 >    Opd64;
        typedef detail::Opd$<   80 >    Opd80;
        typedef detail::Opd$<  128 >    Opd128;
        typedef detail::Opd$<  224 >    Opd224;
        typedef detail::Opd$<  256 >    Opd256;
        typedef detail::Opd$<  864 >    Opd864;
        typedef detail::Opd$< 4096 >    Opd4096;

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
        typedef Mem$<Opd8>      Mem8;
        typedef Mem$<Opd16>     Mem16;
        typedef Mem$<Opd32>     Mem32;
        typedef Mem$<Opd64>     Mem64;
        typedef Mem$<Opd80>     Mem80;
        typedef Mem$<Opd128>    Mem128;
        typedef Mem$<Opd224>    Mem224;     // FPU environment
        typedef Mem$<Opd256>    Mem256;
        typedef Mem$<Opd864>    Mem864;     // FPU state
        typedef Mem$<Opd4096>   Mem4096;    // FPU, MMX, XMM, MXCSR state

        template< class OpdN, OpdSize IndexSize >
        struct VecMem$ : OpdN
        {
            VecMem$(OpdSize base_size, RegID const & base, RegID const & index, sint64 scale, sint64 disp) : OpdN(base_size, IndexSize, base, index, scale, disp) {}
        };
        typedef VecMem$< Opd32, O_SIZE_128 >    Mem32vxd;
        typedef VecMem$< Opd32, O_SIZE_256 >    Mem32vyd;
        typedef VecMem$< Opd32, O_SIZE_128 >    Mem64vxd;
        typedef VecMem$< Opd32, O_SIZE_256 >    Mem64vyd;
        typedef VecMem$< Opd64, O_SIZE_128 >    Mem32vxq;
        typedef VecMem$< Opd64, O_SIZE_256 >    Mem32vyq;
        typedef VecMem$< Opd64, O_SIZE_128 >    Mem64vxq;
        typedef VecMem$< Opd64, O_SIZE_256 >    Mem64vyq;

        template< class OpdN, class U, class S >
        struct Imm$ : OpdN
        {
            Imm$(U imm) : OpdN((S)imm) {}
        };
        typedef Imm$<Opd8, uint8, sint8>    Imm8;   ///< 1 byte immediate
        typedef Imm$<Opd16, uint16, sint16> Imm16;  ///< 2 byte immediate
        typedef Imm$<Opd32, uint32, sint32> Imm32;  ///< 4 byte immediate
        typedef Imm$<Opd64, uint64, sint64> Imm64;  ///< 8 byte immediate

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
            {}  // implicit
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
            I_INVALID = 0,

            I_AAA,
            I_AAD,
            I_AAM,
            I_AAS,
            I_ADC,
            I_ADCX,
            I_ADD,
            I_ADDPD,
            I_ADDPS,
            I_ADDSD,
            I_ADDSS,
            I_ADDSUBPD,
            I_ADDSUBPS,
            I_ADOX,
            I_AESDEC,
            I_AESDECLAST,
            I_AESENC,
            I_AESENCLAST,
            I_AESIMC,
            I_AESKEYGENASSIST,
            I_AND,
            I_ANDN,
            I_ANDNPD,
            I_ANDNPS,
            I_ANDPD,
            I_ANDPS,
            I_ARPL,
            I_BEXTR,
            I_BLCFILL,
            I_BLCI,
            I_BLCIC,
            I_BLCMSK,
            I_BLCS,
            I_BLENDPD,
            I_BLENDPS,
            I_BLENDVPD,
            I_BLENDVPS,
            I_BLSFILL,
            I_BLSI,
            I_BLSIC,
            I_BLSMSK,
            I_BLSR,
            I_BOUND,
            I_BSF,
            I_BSR,
            I_BSWAP,
            I_BT,
            I_BTC,
            I_BTR,
            I_BTS,
            I_BZHI,
            I_CALL,
            I_CBW,
            I_CDQ,
            I_CDQE,
            I_CLAC,
            I_CLC,
            I_CLD,
            I_CLFLUSH,
            I_CLGI,
            I_CLI,
            I_CLTS,
            I_CMC,
            I_CMOVCC,
            I_CMP,
            I_CMPPD,
            I_CMPPS,
            I_CMPS,
            I_CMPSD,
            I_CMPSS,
            I_CMPXCHG,
            I_CMPXCHG16B,
            I_CMPXCHG8B,
            I_COMISD,
            I_COMISS,
            I_CPUID,
            I_CQO,
            I_CRC32,
            I_CVTDQ2PD,
            I_CVTDQ2PS,
            I_CVTPD2DQ,
            I_CVTPD2PI,
            I_CVTPD2PS,
            I_CVTPI2PD,
            I_CVTPI2PS,
            I_CVTPS2DQ,
            I_CVTPS2PD,
            I_CVTPS2PI,
            I_CVTSD2SI,
            I_CVTSD2SS,
            I_CVTSI2SD,
            I_CVTSI2SS,
            I_CVTSS2SD,
            I_CVTSS2SI,
            I_CVTTPD2DQ,
            I_CVTTPD2PI,
            I_CVTTPS2DQ,
            I_CVTTPS2PI,
            I_CVTTSD2SI,
            I_CVTTSS2SI,
            I_CWD,
            I_CWDE,
            I_DAA,
            I_DAS,
            I_DATA16,
            I_DEC,
            I_DIV,
            I_DIVPD,
            I_DIVPS,
            I_DIVSD,
            I_DIVSS,
            I_DPPD,
            I_DPPS,
            I_EMMS,
            I_ENCLS,
            I_ENCLU,
            I_ENTER,
            I_EXTRACTPS,
            I_EXTRQ,
            I_F2XM1,
            I_FABS,
            I_FADD,
            I_FADDP,
            I_FBLD,
            I_FBSTP,
            I_FCHS,
            I_FCMOVCC,
            I_FCOM,
            I_FCOMI,
            I_FCOMP,
            I_FCOMPI,
            I_FCOMPP,
            I_FCOS,
            I_FDECSTP,
            I_FDIV,
            I_FDIVP,
            I_FDIVR,
            I_FDIVRP,
            I_FEMMS,
            I_FFREE,
            I_FIADD,
            I_FICOM,
            I_FICOMP,
            I_FIDIV,
            I_FIDIVR,
            I_FILD,
            I_FIMUL,
            I_FINCSTP,
            I_FIST,
            I_FISTP,
            I_FISTTP,
            I_FISUB,
            I_FISUBR,
            I_FLD,
            I_FLD1,
            I_FLDCW,
            I_FLDENV,
            I_FLDL2E,
            I_FLDL2T,
            I_FLDLG2,
            I_FLDLN2,
            I_FLDPI,
            I_FLDZ,
            I_FMUL,
            I_FMULP,
            I_FNCLEX,
            I_FNINIT,
            I_FNOP,
            I_FNSAVE,
            I_FNSTCW,
            I_FNSTENV,
            I_FNSTSW,
            I_FPATAN,
            I_FPREM,
            I_FPREM1,
            I_FPTAN,
            I_FRNDINT,
            I_FRSTOR,
            I_FSCALE,
            I_FSETPM,
            I_FSIN,
            I_FSINCOS,
            I_FSQRT,
            I_FST,
            I_FSTP,
            I_FSTPNCE,
            I_FSUB,
            I_FSUBP,
            I_FSUBR,
            I_FSUBRP,
            I_FTST,
            I_FUCOM,
            I_FUCOMI,
            I_FUCOMP,
            I_FUCOMPI,
            I_FUCOMPP,
            I_FXAM,
            I_FXCH,
            I_FXRSTOR,
            I_FXRSTOR64,
            I_FXSAVE,
            I_FXSAVE64,
            I_FXTRACT,
            I_FYL2X,
            I_FYL2XP1,
            I_GETSEC,
            I_HADDPD,
            I_HADDPS,
            I_HLT,
            I_HSUBPD,
            I_HSUBPS,
            I_IDIV,
            I_IMUL,
            I_IN,
            I_INC,
            I_INS,
            I_INSERTPS,
            I_INSERTQ,
            I_INT,
            I_INT1,
            I_INT3,
            I_INTO,
            I_INVD,
            I_INVEPT,
            I_INVLPG,
            I_INVLPGA,
            I_INVPCID,
            I_INVVPID,
            I_IRET,
            I_IRETD,
            I_IRETQ,
            I_JCC,
            I_JMP,
            I_KANDB,
            I_KANDD,
            I_KANDNB,
            I_KANDND,
            I_KANDNQ,
            I_KANDNW,
            I_KANDQ,
            I_KANDW,
            I_KMOVB,
            I_KMOVD,
            I_KMOVQ,
            I_KMOVW,
            I_KNOTB,
            I_KNOTD,
            I_KNOTQ,
            I_KNOTW,
            I_KORB,
            I_KORD,
            I_KORQ,
            I_KORTESTW,
            I_KORW,
            I_KSHIFTLW,
            I_KSHIFTRW,
            I_KUNPCKBW,
            I_KXNORB,
            I_KXNORD,
            I_KXNORQ,
            I_KXNORW,
            I_KXORB,
            I_KXORD,
            I_KXORQ,
            I_KXORW,
            I_LAHF,
            I_LAR,
            I_LCALL,
            I_LDDQU,
            I_LDMXCSR,
            I_LDS,
            I_LEA,
            I_LEAVE,
            I_LES,
            I_LFENCE,
            I_LFS,
            I_LGDT,
            I_LGS,
            I_LIDT,
            I_LJMP,
            I_LLDT,
            I_LMSW,
            I_LOCK,
            I_LODS,
            I_LSL,
            I_LSS,
            I_LTR,
            I_LZCNT,
            I_MASKMOVDQU,
            I_MASKMOVQ,
            I_MAXPD,
            I_MAXPS,
            I_MAXSD,
            I_MAXSS,
            I_MFENCE,
            I_MINPD,
            I_MINPS,
            I_MINSD,
            I_MINSS,
            I_MONITOR,
            I_MONTMUL,
            I_MOV,
            I_MOVABS,
            I_MOVAPD,
            I_MOVAPS,
            I_MOVBE,
            I_MOVD,
            I_MOVDDUP,
            I_MOVDQ2Q,
            I_MOVDQA,
            I_MOVDQU,
            I_MOVHLPS,
            I_MOVHPD,
            I_MOVHPS,
            I_MOVLHPS,
            I_MOVLPD,
            I_MOVLPS,
            I_MOVMSKPD,
            I_MOVMSKPS,
            I_MOVNTDQ,
            I_MOVNTDQA,
            I_MOVNTI,
            I_MOVNTPD,
            I_MOVNTPS,
            I_MOVNTQ,
            I_MOVNTSD,
            I_MOVNTSS,
            I_MOVQ,
            I_MOVQ2DQ,
            I_MOVS,
            I_MOVSD,
            I_MOVSHDUP,
            I_MOVSLDUP,
            I_MOVSS,
            I_MOVSX,
            I_MOVSXD,
            I_MOVUPD,
            I_MOVUPS,
            I_MOVZX,
            I_MPSADBW,
            I_MUL,
            I_MULPD,
            I_MULPS,
            I_MULSD,
            I_MULSS,
            I_MULX,
            I_MWAIT,
            I_NEG,
            I_NOP,
            I_NOT,
            I_OR,
            I_ORPD,
            I_ORPS,
            I_OUT,
            I_OUTS,
            I_PABSB,
            I_PABSD,
            I_PABSW,
            I_PACKSSDW,
            I_PACKSSWB,
            I_PACKUSDW,
            I_PACKUSWB,
            I_PADDB,
            I_PADDD,
            I_PADDQ,
            I_PADDSB,
            I_PADDSW,
            I_PADDUSB,
            I_PADDUSW,
            I_PADDW,
            I_PALIGNR,
            I_PAND,
            I_PANDN,
            I_PAUSE,
            I_PAVGB,
            I_PAVGUSB,
            I_PAVGW,
            I_PBLENDVB,
            I_PBLENDW,
            I_PCLMULQDQ,
            I_PCMPEQB,
            I_PCMPEQD,
            I_PCMPEQQ,
            I_PCMPEQW,
            I_PCMPESTRI,
            I_PCMPESTRM,
            I_PCMPGTB,
            I_PCMPGTD,
            I_PCMPGTQ,
            I_PCMPGTW,
            I_PCMPISTRI,
            I_PCMPISTRM,
            I_PDEP,
            I_PEXT,
            I_PEXTRB,
            I_PEXTRD,
            I_PEXTRQ,
            I_PEXTRW,
            I_PF2ID,
            I_PF2IW,
            I_PFACC,
            I_PFADD,
            I_PFCMPEQ,
            I_PFCMPGE,
            I_PFCMPGT,
            I_PFMAX,
            I_PFMIN,
            I_PFMUL,
            I_PFNACC,
            I_PFPNACC,
            I_PFRCP,
            I_PFRCPIT1,
            I_PFRCPIT2,
            I_PFRSQIT1,
            I_PFRSQRT,
            I_PFSUB,
            I_PFSUBR,
            I_PHADDD,
            I_PHADDSW,
            I_PHADDW,
            I_PHMINPOSUW,
            I_PHSUBD,
            I_PHSUBSW,
            I_PHSUBW,
            I_PI2FD,
            I_PI2FW,
            I_PINSRB,
            I_PINSRD,
            I_PINSRQ,
            I_PINSRW,
            I_PMADDUBSW,
            I_PMADDWD,
            I_PMAXSB,
            I_PMAXSD,
            I_PMAXSW,
            I_PMAXUB,
            I_PMAXUD,
            I_PMAXUW,
            I_PMINSB,
            I_PMINSD,
            I_PMINSW,
            I_PMINUB,
            I_PMINUD,
            I_PMINUW,
            I_PMOVMSKB,
            I_PMOVSXBD,
            I_PMOVSXBQ,
            I_PMOVSXBW,
            I_PMOVSXDQ,
            I_PMOVSXWD,
            I_PMOVSXWQ,
            I_PMOVZXBD,
            I_PMOVZXBQ,
            I_PMOVZXBW,
            I_PMOVZXDQ,
            I_PMOVZXWD,
            I_PMOVZXWQ,
            I_PMULDQ,
            I_PMULHRSW,
            I_PMULHRW,
            I_PMULHUW,
            I_PMULHW,
            I_PMULLD,
            I_PMULLW,
            I_PMULUDQ,
            I_POP,
            I_POPA,
            I_POPAD,
            I_POPCNT,
            I_POPF,
            I_POPFD,
            I_POPFQ,
            I_POR,
            I_PREFETCH,
            I_PREFETCHNTA,
            I_PREFETCHT0,
            I_PREFETCHT1,
            I_PREFETCHT2,
            I_PREFETCHW,
            I_PSADBW,
            I_PSHUFB,
            I_PSHUFD,
            I_PSHUFHW,
            I_PSHUFLW,
            I_PSHUFW,
            I_PSIGNB,
            I_PSIGND,
            I_PSIGNW,
            I_PSLLD,
            I_PSLLDQ,
            I_PSLLQ,
            I_PSLLW,
            I_PSRAD,
            I_PSRAW,
            I_PSRLD,
            I_PSRLDQ,
            I_PSRLQ,
            I_PSRLW,
            I_PSUBB,
            I_PSUBD,
            I_PSUBQ,
            I_PSUBSB,
            I_PSUBSW,
            I_PSUBUSB,
            I_PSUBUSW,
            I_PSUBW,
            I_PSWAPD,
            I_PTEST,
            I_PUNPCKHBW,
            I_PUNPCKHDQ,
            I_PUNPCKHQDQ,
            I_PUNPCKHWD,
            I_PUNPCKLBW,
            I_PUNPCKLDQ,
            I_PUNPCKLQDQ,
            I_PUNPCKLWD,
            I_PUSH,
            I_PUSHA,
            I_PUSHAD,
            I_PUSHF,
            I_PUSHFD,
            I_PUSHFQ,
            I_PXOR,
            I_RCL,
            I_RCPPS,
            I_RCPSS,
            I_RCR,
            I_RDFSBASE,
            I_RDGSBASE,
            I_RDMSR,
            I_RDPMC,
            I_RDRAND,
            I_RDSEED,
            I_RDTSC,
            I_RDTSCP,
            I_REP,
            I_REPNE,
            I_RET,
            I_RETF,
            I_RETFQ,
            I_ROL,
            I_ROR,
            I_RORX,
            I_ROUNDPD,
            I_ROUNDPS,
            I_ROUNDSD,
            I_ROUNDSS,
            I_RSM,
            I_RSQRTPS,
            I_RSQRTSS,
            I_SAHF,
            I_SAL,
            I_SALC,
            I_SAR,
            I_SARX,
            I_SBB,
            I_SCAS,
            I_SETCC,
            I_SFENCE,
            I_SGDT,
            I_SHA1MSG1,
            I_SHA1MSG2,
            I_SHA1NEXTE,
            I_SHA1RNDS4,
            I_SHA256MSG1,
            I_SHA256MSG2,
            I_SHA256RNDS2,
            I_SHL,
            I_SHLD,
            I_SHLX,
            I_SHR,
            I_SHRD,
            I_SHRX,
            I_SHUFPD,
            I_SHUFPS,
            I_SIDT,
            I_SKINIT,
            I_SLDT,
            I_SMSW,
            I_SQRTPD,
            I_SQRTPS,
            I_SQRTSD,
            I_SQRTSS,
            I_STAC,
            I_STC,
            I_STD,
            I_STGI,
            I_STI,
            I_STMXCSR,
            I_STOS,
            I_STR,
            I_SUB,
            I_SUBPD,
            I_SUBPS,
            I_SUBSD,
            I_SUBSS,
            I_SWAPGS,
            I_SYSCALL,
            I_SYSENTER,
            I_SYSEXIT,
            I_SYSRET,
            I_T1MSKC,
            I_TEST,
            I_TZCNT,
            I_TZMSK,
            I_UCOMISD,
            I_UCOMISS,
            I_UD2,
            I_UD2B,
            I_UNPCKHPD,
            I_UNPCKHPS,
            I_UNPCKLPD,
            I_UNPCKLPS,
            I_VADDPD,
            I_VADDPS,
            I_VADDSD,
            I_VADDSS,
            I_VADDSUBPD,
            I_VADDSUBPS,
            I_VAESDEC,
            I_VAESDECLAST,
            I_VAESENC,
            I_VAESENCLAST,
            I_VAESIMC,
            I_VAESKEYGENASSIST,
            I_VALIGND,
            I_VALIGNQ,
            I_VANDNPD,
            I_VANDNPS,
            I_VANDPD,
            I_VANDPS,
            I_VBLENDMPD,
            I_VBLENDMPS,
            I_VBLENDPD,
            I_VBLENDPS,
            I_VBLENDVPD,
            I_VBLENDVPS,
            I_VBROADCASTF128,
            I_VBROADCASTI128,
            I_VBROADCASTI32X4,
            I_VBROADCASTI64X4,
            I_VBROADCASTSD,
            I_VBROADCASTSS,
            I_VCMP,
            I_VCMPPD,
            I_VCMPPS,
            I_VCMPSD,
            I_VCMPSS,
            I_VCOMISD,
            I_VCOMISS,
            I_VCVTDQ2PD,
            I_VCVTDQ2PS,
            I_VCVTPD2DQ,
            I_VCVTPD2DQX,
            I_VCVTPD2PS,
            I_VCVTPD2PSX,
            I_VCVTPD2UDQ,
            I_VCVTPH2PS,
            I_VCVTPS2DQ,
            I_VCVTPS2PD,
            I_VCVTPS2PH,
            I_VCVTPS2UDQ,
            I_VCVTSD2SI,
            I_VCVTSD2SS,
            I_VCVTSD2USI,
            I_VCVTSI2SD,
            I_VCVTSI2SS,
            I_VCVTSS2SD,
            I_VCVTSS2SI,
            I_VCVTSS2USI,
            I_VCVTTPD2DQ,
            I_VCVTTPD2DQX,
            I_VCVTTPD2UDQ,
            I_VCVTTPS2DQ,
            I_VCVTTPS2UDQ,
            I_VCVTTSD2SI,
            I_VCVTTSD2USI,
            I_VCVTTSS2SI,
            I_VCVTTSS2USI,
            I_VCVTUDQ2PD,
            I_VCVTUDQ2PS,
            I_VCVTUSI2SD,
            I_VCVTUSI2SS,
            I_VDIVPD,
            I_VDIVPS,
            I_VDIVSD,
            I_VDIVSS,
            I_VDPPD,
            I_VDPPS,
            I_VERR,
            I_VERW,
            I_VEXTRACTF128,
            I_VEXTRACTF32X4,
            I_VEXTRACTF64X4,
            I_VEXTRACTI128,
            I_VEXTRACTI32X4,
            I_VEXTRACTI64X4,
            I_VEXTRACTPS,
            I_VFMADD132PD,
            I_VFMADD132PS,
            I_VFMADD132SD,
            I_VFMADD132SS,
            I_VFMADD213PD,
            I_VFMADD213PS,
            I_VFMADD213SD,
            I_VFMADD213SS,
            I_VFMADD231PD,
            I_VFMADD231PS,
            I_VFMADD231SD,
            I_VFMADD231SS,
            I_VFMADDPD,
            I_VFMADDPS,
            I_VFMADDSD,
            I_VFMADDSS,
            I_VFMADDSUB132PD,
            I_VFMADDSUB132PS,
            I_VFMADDSUB213PD,
            I_VFMADDSUB213PS,
            I_VFMADDSUB231PD,
            I_VFMADDSUB231PS,
            I_VFMADDSUBPD,
            I_VFMADDSUBPS,
            I_VFMSUB132PD,
            I_VFMSUB132PS,
            I_VFMSUB132SD,
            I_VFMSUB132SS,
            I_VFMSUB213PD,
            I_VFMSUB213PS,
            I_VFMSUB213SD,
            I_VFMSUB213SS,
            I_VFMSUB231PD,
            I_VFMSUB231PS,
            I_VFMSUB231SD,
            I_VFMSUB231SS,
            I_VFMSUBADD132PD,
            I_VFMSUBADD132PS,
            I_VFMSUBADD213PD,
            I_VFMSUBADD213PS,
            I_VFMSUBADD231PD,
            I_VFMSUBADD231PS,
            I_VFMSUBADDPD,
            I_VFMSUBADDPS,
            I_VFMSUBPD,
            I_VFMSUBPS,
            I_VFMSUBSD,
            I_VFMSUBSS,
            I_VFNMADD132PD,
            I_VFNMADD132PS,
            I_VFNMADD132SD,
            I_VFNMADD132SS,
            I_VFNMADD213PD,
            I_VFNMADD213PS,
            I_VFNMADD213SD,
            I_VFNMADD213SS,
            I_VFNMADD231PD,
            I_VFNMADD231PS,
            I_VFNMADD231SD,
            I_VFNMADD231SS,
            I_VFNMADDPD,
            I_VFNMADDPS,
            I_VFNMADDSD,
            I_VFNMADDSS,
            I_VFNMSUB132PD,
            I_VFNMSUB132PS,
            I_VFNMSUB132SD,
            I_VFNMSUB132SS,
            I_VFNMSUB213PD,
            I_VFNMSUB213PS,
            I_VFNMSUB213SD,
            I_VFNMSUB213SS,
            I_VFNMSUB231PD,
            I_VFNMSUB231PS,
            I_VFNMSUB231SD,
            I_VFNMSUB231SS,
            I_VFNMSUBPD,
            I_VFNMSUBPS,
            I_VFNMSUBSD,
            I_VFNMSUBSS,
            I_VFRCZPD,
            I_VFRCZPS,
            I_VFRCZSD,
            I_VFRCZSS,
            I_VGATHERDPD,
            I_VGATHERDPS,
            I_VGATHERPF0DPD,
            I_VGATHERPF0DPS,
            I_VGATHERPF0QPD,
            I_VGATHERPF0QPS,
            I_VGATHERPF1DPD,
            I_VGATHERPF1DPS,
            I_VGATHERPF1QPD,
            I_VGATHERPF1QPS,
            I_VGATHERQPD,
            I_VGATHERQPS,
            I_VHADDPD,
            I_VHADDPS,
            I_VHSUBPD,
            I_VHSUBPS,
            I_VINSERTF128,
            I_VINSERTF32X4,
            I_VINSERTF64X4,
            I_VINSERTI128,
            I_VINSERTI32X4,
            I_VINSERTI64X4,
            I_VINSERTPS,
            I_VLDDQU,
            I_VLDMXCSR,
            I_VMASKMOVDQU,
            I_VMASKMOVPD,
            I_VMASKMOVPS,
            I_VMAXPD,
            I_VMAXPS,
            I_VMAXSD,
            I_VMAXSS,
            I_VMCALL,
            I_VMCLEAR,
            I_VMFUNC,
            I_VMINPD,
            I_VMINPS,
            I_VMINSD,
            I_VMINSS,
            I_VMLAUNCH,
            I_VMLOAD,
            I_VMMCALL,
            I_VMOVAPD,
            I_VMOVAPS,
            I_VMOVD,
            I_VMOVDDUP,
            I_VMOVDQA,
            I_VMOVDQA32,
            I_VMOVDQA64,
            I_VMOVDQU,
            I_VMOVDQU16,
            I_VMOVDQU32,
            I_VMOVDQU64,
            I_VMOVDQU8,
            I_VMOVHLPS,
            I_VMOVHPD,
            I_VMOVHPS,
            I_VMOVLHPS,
            I_VMOVLPD,
            I_VMOVLPS,
            I_VMOVMSKPD,
            I_VMOVMSKPS,
            I_VMOVNTDQ,
            I_VMOVNTDQA,
            I_VMOVNTPD,
            I_VMOVNTPS,
            I_VMOVQ,
            I_VMOVSD,
            I_VMOVSHDUP,
            I_VMOVSLDUP,
            I_VMOVSS,
            I_VMOVUPD,
            I_VMOVUPS,
            I_VMPSADBW,
            I_VMPTRLD,
            I_VMPTRST,
            I_VMREAD,
            I_VMRESUME,
            I_VMRUN,
            I_VMSAVE,
            I_VMULPD,
            I_VMULPS,
            I_VMULSD,
            I_VMULSS,
            I_VMWRITE,
            I_VMXOFF,
            I_VMXON,
            I_VORPD,
            I_VORPS,
            I_VPABSB,
            I_VPABSD,
            I_VPABSQ,
            I_VPABSW,
            I_VPACKSSDW,
            I_VPACKSSWB,
            I_VPACKUSDW,
            I_VPACKUSWB,
            I_VPADDB,
            I_VPADDD,
            I_VPADDQ,
            I_VPADDSB,
            I_VPADDSW,
            I_VPADDUSB,
            I_VPADDUSW,
            I_VPADDW,
            I_VPALIGNR,
            I_VPAND,
            I_VPANDD,
            I_VPANDN,
            I_VPANDND,
            I_VPANDNQ,
            I_VPANDQ,
            I_VPAVGB,
            I_VPAVGW,
            I_VPBLENDD,
            I_VPBLENDMD,
            I_VPBLENDMQ,
            I_VPBLENDVB,
            I_VPBLENDW,
            I_VPBROADCASTB,
            I_VPBROADCASTD,
            I_VPBROADCASTMB2Q,
            I_VPBROADCASTMW2D,
            I_VPBROADCASTQ,
            I_VPBROADCASTW,
            I_VPCLMULQDQ,
            I_VPCMOV,
            I_VPCMP,
            I_VPCMPD,
            I_VPCMPEQB,
            I_VPCMPEQD,
            I_VPCMPEQQ,
            I_VPCMPEQW,
            I_VPCMPESTRI,
            I_VPCMPESTRM,
            I_VPCMPGTB,
            I_VPCMPGTD,
            I_VPCMPGTQ,
            I_VPCMPGTW,
            I_VPCMPISTRI,
            I_VPCMPISTRM,
            I_VPCMPQ,
            I_VPCMPUD,
            I_VPCMPUQ,
            I_VPCOMB,
            I_VPCOMD,
            I_VPCOMQ,
            I_VPCOMUB,
            I_VPCOMUD,
            I_VPCOMUQ,
            I_VPCOMUW,
            I_VPCOMW,
            I_VPCONFLICTD,
            I_VPCONFLICTQ,
            I_VPERM2F128,
            I_VPERM2I128,
            I_VPERMD,
            I_VPERMI2D,
            I_VPERMI2PD,
            I_VPERMI2PS,
            I_VPERMI2Q,
            I_VPERMIL2PD,
            I_VPERMIL2PS,
            I_VPERMILPD,
            I_VPERMILPS,
            I_VPERMPD,
            I_VPERMPS,
            I_VPERMQ,
            I_VPERMT2D,
            I_VPERMT2PD,
            I_VPERMT2PS,
            I_VPERMT2Q,
            I_VPEXTRB,
            I_VPEXTRD,
            I_VPEXTRQ,
            I_VPEXTRW,
            I_VPGATHERDD,
            I_VPGATHERDQ,
            I_VPGATHERQD,
            I_VPGATHERQQ,
            I_VPHADDBD,
            I_VPHADDBQ,
            I_VPHADDBW,
            I_VPHADDD,
            I_VPHADDDQ,
            I_VPHADDSW,
            I_VPHADDUBD,
            I_VPHADDUBQ,
            I_VPHADDUBW,
            I_VPHADDUDQ,
            I_VPHADDUWD,
            I_VPHADDUWQ,
            I_VPHADDW,
            I_VPHADDWD,
            I_VPHADDWQ,
            I_VPHMINPOSUW,
            I_VPHSUBBW,
            I_VPHSUBD,
            I_VPHSUBDQ,
            I_VPHSUBSW,
            I_VPHSUBW,
            I_VPHSUBWD,
            I_VPINSRB,
            I_VPINSRD,
            I_VPINSRQ,
            I_VPINSRW,
            I_VPLZCNTD,
            I_VPLZCNTQ,
            I_VPMACSDD,
            I_VPMACSDQH,
            I_VPMACSDQL,
            I_VPMACSSDD,
            I_VPMACSSDQH,
            I_VPMACSSDQL,
            I_VPMACSSWD,
            I_VPMACSSWW,
            I_VPMACSWD,
            I_VPMACSWW,
            I_VPMADCSSWD,
            I_VPMADCSWD,
            I_VPMADDUBSW,
            I_VPMADDWD,
            I_VPMASKMOVD,
            I_VPMASKMOVQ,
            I_VPMAXSB,
            I_VPMAXSD,
            I_VPMAXSQ,
            I_VPMAXSW,
            I_VPMAXUB,
            I_VPMAXUD,
            I_VPMAXUQ,
            I_VPMAXUW,
            I_VPMINSB,
            I_VPMINSD,
            I_VPMINSQ,
            I_VPMINSW,
            I_VPMINUB,
            I_VPMINUD,
            I_VPMINUQ,
            I_VPMINUW,
            I_VPMOVDB,
            I_VPMOVDW,
            I_VPMOVMSKB,
            I_VPMOVQB,
            I_VPMOVQD,
            I_VPMOVQW,
            I_VPMOVSDB,
            I_VPMOVSDW,
            I_VPMOVSQB,
            I_VPMOVSQD,
            I_VPMOVSQW,
            I_VPMOVSXBD,
            I_VPMOVSXBQ,
            I_VPMOVSXBW,
            I_VPMOVSXDQ,
            I_VPMOVSXWD,
            I_VPMOVSXWQ,
            I_VPMOVUSDB,
            I_VPMOVUSDW,
            I_VPMOVUSQB,
            I_VPMOVUSQD,
            I_VPMOVUSQW,
            I_VPMOVZXBD,
            I_VPMOVZXBQ,
            I_VPMOVZXBW,
            I_VPMOVZXDQ,
            I_VPMOVZXWD,
            I_VPMOVZXWQ,
            I_VPMULDQ,
            I_VPMULHRSW,
            I_VPMULHUW,
            I_VPMULHW,
            I_VPMULLD,
            I_VPMULLW,
            I_VPMULUDQ,
            I_VPOR,
            I_VPORD,
            I_VPORQ,
            I_VPPERM,
            I_VPROTB,
            I_VPROTD,
            I_VPROTQ,
            I_VPROTW,
            I_VPSADBW,
            I_VPSCATTERDD,
            I_VPSCATTERDQ,
            I_VPSCATTERQD,
            I_VPSCATTERQQ,
            I_VPSHAB,
            I_VPSHAD,
            I_VPSHAQ,
            I_VPSHAW,
            I_VPSHLB,
            I_VPSHLD,
            I_VPSHLQ,
            I_VPSHLW,
            I_VPSHUFB,
            I_VPSHUFD,
            I_VPSHUFHW,
            I_VPSHUFLW,
            I_VPSIGNB,
            I_VPSIGND,
            I_VPSIGNW,
            I_VPSLLD,
            I_VPSLLDQ,
            I_VPSLLQ,
            I_VPSLLVD,
            I_VPSLLVQ,
            I_VPSLLW,
            I_VPSRAD,
            I_VPSRAQ,
            I_VPSRAVD,
            I_VPSRAVQ,
            I_VPSRAW,
            I_VPSRLD,
            I_VPSRLDQ,
            I_VPSRLQ,
            I_VPSRLVD,
            I_VPSRLVQ,
            I_VPSRLW,
            I_VPSUBB,
            I_VPSUBD,
            I_VPSUBQ,
            I_VPSUBSB,
            I_VPSUBSW,
            I_VPSUBUSB,
            I_VPSUBUSW,
            I_VPSUBW,
            I_VPTEST,
            I_VPTESTMD,
            I_VPTESTMQ,
            I_VPTESTNMD,
            I_VPTESTNMQ,
            I_VPUNPCKHBW,
            I_VPUNPCKHDQ,
            I_VPUNPCKHQDQ,
            I_VPUNPCKHWD,
            I_VPUNPCKLBW,
            I_VPUNPCKLDQ,
            I_VPUNPCKLQDQ,
            I_VPUNPCKLWD,
            I_VPXOR,
            I_VPXORD,
            I_VPXORQ,
            I_VRCP14PD,
            I_VRCP14PS,
            I_VRCP14SD,
            I_VRCP14SS,
            I_VRCP28PD,
            I_VRCP28PS,
            I_VRCP28SD,
            I_VRCP28SS,
            I_VRCPPS,
            I_VRCPSS,
            I_VRNDSCALEPD,
            I_VRNDSCALEPS,
            I_VRNDSCALESD,
            I_VRNDSCALESS,
            I_VROUNDPD,
            I_VROUNDPS,
            I_VROUNDSD,
            I_VROUNDSS,
            I_VRSQRT14PD,
            I_VRSQRT14PS,
            I_VRSQRT14SD,
            I_VRSQRT14SS,
            I_VRSQRT28PD,
            I_VRSQRT28PS,
            I_VRSQRT28SD,
            I_VRSQRT28SS,
            I_VRSQRTPS,
            I_VRSQRTSS,
            I_VSCATTERDPD,
            I_VSCATTERDPS,
            I_VSCATTERPF0DPD,
            I_VSCATTERPF0DPS,
            I_VSCATTERPF0QPD,
            I_VSCATTERPF0QPS,
            I_VSCATTERPF1DPD,
            I_VSCATTERPF1DPS,
            I_VSCATTERPF1QPD,
            I_VSCATTERPF1QPS,
            I_VSCATTERQPD,
            I_VSCATTERQPS,
            I_VSHUFPD,
            I_VSHUFPS,
            I_VSQRTPD,
            I_VSQRTPS,
            I_VSQRTSD,
            I_VSQRTSS,
            I_VSTMXCSR,
            I_VSUBPD,
            I_VSUBPS,
            I_VSUBSD,
            I_VSUBSS,
            I_VTESTPD,
            I_VTESTPS,
            I_VUCOMISD,
            I_VUCOMISS,
            I_VUNPCKHPD,
            I_VUNPCKHPS,
            I_VUNPCKLPD,
            I_VUNPCKLPS,
            I_VXORPD,
            I_VXORPS,
            I_VZEROALL,
            I_VZEROUPPER,
            I_WAIT,
            I_WBINVD,
            I_WRFSBASE,
            I_WRGSBASE,
            I_WRMSR,
            I_XABORT,
            I_XACQUIRE,
            I_XADD,
            I_XBEGIN,
            I_XCHG,
            I_XCRYPTCBC,
            I_XCRYPTCFB,
            I_XCRYPTCTR,
            I_XCRYPTECB,
            I_XCRYPTOFB,
            I_XEND,
            I_XGETBV,
            I_XLAT,
            I_XOR,
            I_XORPD,
            I_XORPS,
            I_XRELEASE,
            I_XRSTOR,
            I_XRSTOR64,
            I_XSAVE,
            I_XSAVE64,
            I_XSAVEOPT,
            I_XSAVEOPT64,
            I_XSETBV,
            I_XSHA1,
            I_XSHA256,
            I_XSTORE,
            I_XTEST,

            I_LAST_INSTRUCTION,

            // jitasm compiler instructions
            I_COMPILER_DECLARE_REG_ARG,     ///< Declare register argument
            I_COMPILER_DECLARE_STACK_ARG,   ///< Declare stack argument
            I_COMPILER_DECLARE_RESULT_REG,  ///< Declare result register (eax/rax/xmm0)
            I_COMPILER_PROLOG,              ///< Function prolog
            I_COMPILER_EPILOG,              ///< Function epilog

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
            JCC_LOOPE = 0x70, JCC_LOOPNE, JCC_RCXNZ, JCC_RCXZ
        };

        enum ConditionCode
        {
            CC_O, CC_NO, CC_B, CC_AE, CC_E, CC_NE, CC_BE, CC_A, CC_S, CC_NS, CC_P, CC_NP, CC_L, CC_GE, CC_LE, CC_G,
        };

        enum EncodingFlags
        {
            E_SPECIAL = 1 << 0,
            E_OPERAND_SIZE_PREFIX = 1 << 1, ///< Operand-size override prefix
            E_REP_PREFIX = 1 << 2,  ///< REP prefix
            E_REXW_PREFIX = 1 << 3, ///< REX.W
            E_MANDATORY_PREFIX_66 = 1 << 4, ///< Mandatory prefix 66
            E_MANDATORY_PREFIX_F2 = 1 << 5, ///< Mandatory prefix F2
            E_MANDATORY_PREFIX_F3 = 1 << 6, ///< Mandatory prefix F3
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
            E_VEX_128_0F = E_VEX_128 | E_VEX_0F,
            E_VEX_256_0F = E_VEX_256 | E_VEX_0F,
            E_VEX_128_66_0F = E_VEX_128 | E_VEX_66_0F,
            E_VEX_256_66_0F = E_VEX_256 | E_VEX_66_0F,
            E_VEX_128_66_0F38 = E_VEX_128 | E_VEX_66_0F38,
            E_VEX_256_66_0F38 = E_VEX_256 | E_VEX_66_0F38,
            E_VEX_128_0F_WIG = E_VEX_128_0F | E_VEX_WIG,
            E_VEX_256_0F_WIG = E_VEX_256_0F | E_VEX_WIG,
            E_VEX_128_66_0F_WIG = E_VEX_128_66_0F | E_VEX_WIG,
            E_VEX_256_66_0F_WIG = E_VEX_256_66_0F | E_VEX_WIG,
            E_VEX_128_66_0F38_WIG = E_VEX_128_66_0F38 | E_VEX_WIG,
            E_VEX_256_66_0F38_WIG = E_VEX_256_66_0F38 | E_VEX_WIG,
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

            InstrID     id_;
            uint32      opcode_;
            uint32      encoding_flags_;
            detail::Opd opd_[MAX_OPERAND_COUNT];
            
            Instr(
                InstrID             id,
                detail::Opd const & opd1 = detail::Opd(),
                detail::Opd const & opd2 = detail::Opd(),
                detail::Opd const & opd3 = detail::Opd(),
                detail::Opd const & opd4 = detail::Opd(),
                detail::Opd const & opd5 = detail::Opd(),
                detail::Opd const & opd6 = detail::Opd())
                : id_(id), opcode_(0), encoding_flags_(0)
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
                : id_(id), opcode_(opcode), encoding_flags_(encoding_flag)
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

            friend __declspec(noinline) bool operator== (Instr const & lhs, Instr const & lhr)
            {
                return
                    lhs.id_ == lhr.id_ &&
                    lhs.opcode_ == lhr.opcode_ &&
                    lhs.encoding_flags_ == lhr.encoding_flags_ &&
                    lhs.opd_[0] == lhr.opd_[0] &&
                    lhs.opd_[1] == lhr.opd_[1] &&
                    lhs.opd_[2] == lhr.opd_[2] &&
                    lhs.opd_[3] == lhr.opd_[3] &&
                    lhs.opd_[4] == lhr.opd_[4] &&
                    lhs.opd_[5] == lhr.opd_[5];
            }
        };

        namespace encoder
        {
            struct True
            {
                static bool Matches(Instr & instr, size_t /*index*/)
                {
                    return true;
                }
            };

            struct False
            {
                static bool Matches(Instr & instr, size_t /*index*/)
                {
                    return false;
                }
            };

            template< typename Operand, typename ...Rest >
            struct Match
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    if (Operand::Matches(instr, index))
                    {
                        return Match< Rest... >::Matches(instr, index + 1);
                    }

                    return false;
                }
            };

            template< typename Operand >
            struct Match < Operand >
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    return Operand::Matches(instr, index);
                }
            };

            template< InstrID id, size_t opcode, typename Operand, typename ...Rest >
            struct Opcode
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (Operand::Matches(instr, 0))
                    {
                        instr.opcode_ |= opcode;
                        instr.encoding_flags_ |= E_ENCODED;

                        return Encode$< id, opcode, Operand, Rest... >::Encode(instr, is64);
                    }

                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    Encode$< id, opcode, Operand, Rest... >::Test(list, is64);
                }
#endif
            };

            template< InstrID id, size_t opcode, typename Operand >
            struct Opcode< id, opcode, Operand >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (Operand::Matches(instr, 0))
                    {
                        instr.opcode_ |= opcode;
                        instr.encoding_flags_ |= E_ENCODED;

                        Encode$< id, opcode, Operand >::Encode(instr, is64);

                        return true;
                    }

                    return false;
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    Encode$< id, opcode, Operand >::Test(list, is64);
                }
#endif
            };

            template< typename Opcode, typename ...Rest >
            struct Switch
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    if (Opcode::Encode(instr, is64))
                    {
                        return true;
                    }

                    return Switch< Rest... >::Encode(instr, is64);
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    Switch< Opcode >::Test(list, is64);
                    Switch< Rest... >::Test(list, is64);
                    std::vector< Instr > unique_list;
                    auto i = list.begin();
                    while (i != list.end())
                    {
                        auto & instr = *i;
                        bool already_found = false;
                        for (auto & unique_instr : unique_list)
                        {
                            already_found = unique_instr == instr;
                            if (already_found)
                            {
                                break;
                            }
                        }
                        if (!already_found)
                        {
                            unique_list.push_back(instr);
                        }
                        ++i;
                    }
                    list.swap(unique_list);
                }
#endif
            };

            template< typename Opcode >
            struct Switch < Opcode >
            {
                static bool Encode(Instr & instr, bool is64)
                {
                    return Opcode::Encode(instr, is64);
                }
#ifdef JITASM_TEST
                static void Test(std::vector< Instr > & list, bool is64)
                {
                    std::vector< Instr > partial_list;
                    Opcode::Test(partial_list, is64);
                    for (auto & instr : partial_list)
                    {
                        list.push_back(instr);
                    }
                }
#endif
            };

            ///////////////////////
            // KEY TO ABBREVIATIONS
            ////
            //  Operands are identified by a two-character code of the form Zz. The first character, an uppercase letter, specifies
            //  the addressing method; the second character, a lowercase letter, specifies the type of operand.

            enum Access { R = 1, W, RW };

            // A

            // B
            template< Access access >
            struct _Bd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        if (O_SIZE_32 == opd.GetSize())
                        {
                            return true;
                        }
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Bq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        if  (O_SIZE_64 == opd.GetSize())
                        {
                            return true;
                        }
                    }

                    return false;
                }
            };

            // C

            // D

            // E
            template< Access access >
            struct _Eb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg() || opd.IsMem())
                    {
                        return O_SIZE_8 == opd.GetSize();
                    }

                    return false;
                }
            };
            template< Access access >
            struct _Ew_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg() || opd.IsMem())
                    {
                        return O_SIZE_16 == opd.GetSize();
                    }

                    return false;
                }
            };
            template< Access access >
            struct _Ed_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg() || opd.IsMem())
                    {
                        return O_SIZE_32 == opd.GetSize();
                    }

                    return false;
                }
            };
            template< Access access >
            struct _Eq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg() || opd.IsMem())
                    {
                        return O_SIZE_64 == opd.GetSize();
                    }

                    return false;
                }
            };

            // F

            // G
            template< Access access >
            struct _Gb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return O_SIZE_8 == opd.GetSize();
                    }

                    return false;
                }
            };
            template< Access access >
            struct _Gw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return O_SIZE_16 == opd.GetSize();
                    }

                    return false;
                }
            };
            template< Access access >
            struct _Gd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return O_SIZE_32 == opd.GetSize();
                    }

                    return false;
                }
            };
            template< Access access >
            struct _Gq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return O_SIZE_64 == opd.GetSize();
                    }

                    return false;
                }
            };

            // H

            // I
            struct _Ib_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsImm())
                    {
                        return detail::IsInt8(opd.GetImm());
                    }

                    return false;
                }
            };
            struct _Iw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsImm())
                    {
                        return detail::IsInt16(opd.GetImm());
                    }

                    return false;
                }
            };
            struct _Id_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsImm())
                    {
                        return detail::IsInt32(opd.GetImm());
                    }

                    return false;
                }
            };

            // J
            struct _Jb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsImm())
                    {
                        return detail::IsInt8(opd.GetImm());
                    }

                    return false;
                }
            };
            struct _Jw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd0 = instr.GetOpd(0);
                    auto & opd1 = instr.GetOpd(index);
                    if (opd1.IsImm())
                    {
                        switch (opd0.GetSize())
                        {
                        case O_SIZE_16:
                            return detail::IsInt16(opd1.GetImm());
                        }
                    }

                    return false;
                }
            };
            struct _Jd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd0 = instr.GetOpd(0);
                    auto & opd1 = instr.GetOpd(index);
                    if (opd1.IsImm())
                    {
                        switch (opd0.GetSize())
                        {
                        case O_SIZE_32:
                        case O_SIZE_64:
                            return detail::IsInt32(opd1.GetImm());
                        }
                    }

                    return false;
                }
            };


            // L

            // M
            template< Access access >
            struct _Mb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    return opd.IsMem() && O_SIZE_8 == opd.GetSize();
                }
            };
            template< Access access >
            struct _Mw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    return opd.IsMem() && O_SIZE_16 == opd.GetSize();
                }
            };
            template< Access access >
            struct _Md_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    return opd.IsMem() && O_SIZE_32 == opd.GetSize();
                }
            };
            template< Access access >
            struct _Mq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    return opd.IsMem() && O_SIZE_64 == opd.GetSize();
                }
            };
            
            template< Access access >
            struct _Mo_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    return opd.IsMem() && O_SIZE_128 == opd.GetSize();
                }
            };
            
            // N

            // O

            // P

            // Q

            // R

            // S

            // T

            // U

            // V

            // W

            // X
            template< Access access >
            struct _Xb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_8 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RSI == reg.id;
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Xw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_16 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RSI == reg.id;
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Xd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_32 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RSI == reg.id;
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Xq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_64 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RSI == reg.id;
                    }

                    return false;
                }
            };

            // Y
            template< Access access >
            struct _Yb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_8 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RDI == reg.id;
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Yw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_16 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RDI == reg.id;
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Yd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_32 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RDI == reg.id;
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Yq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsMem() && O_SIZE_64 == opd.GetSize() && opd.GetIndex().IsInvalid() && !opd.GetScale() && !opd.GetDisp())
                    {
                        auto reg = opd.GetBase();
                        return R_TYPE_GP == reg.GetType() && RDI == reg.id;
                    }

                    return false;
                }
            };

            // Z
            template< Access access >
            struct _Zw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        if (O_SIZE_16 == opd.GetSize())
                        {
                            return true;
                        }
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Zd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        if (O_SIZE_32 == opd.GetSize())
                        {
                            return true;
                        }
                    }

                    return false;
                }
            };

            template< Access access >
            struct _Zq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        if (O_SIZE_64 == opd.GetSize())
                        {
                            return true;
                        }
                    }

                    return false;
                }
            };

            /////////////////////
            // SPECIAL DYMMY KEYS

            template< PhysicalRegID id, Access access >
            struct _rb_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    if (index < 0) // dummy register
                    {
                        return true;
                    }
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return id == opd.GetReg().id && O_SIZE_8 == opd.GetSize();
                    }

                    return false;
                }
            };

            template< PhysicalRegID id, Access access >
            struct _rw_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return id == opd.GetReg().id && O_SIZE_16 == opd.GetSize();
                    }

                    return false;
                }
            };

            template< PhysicalRegID id, Access access >
            struct _rd_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return id == opd.GetReg().id && O_SIZE_32 == opd.GetSize();
                    }

                    return false;
                }
            };

            template< PhysicalRegID id, Access access >
            struct _rq_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return id == opd.GetReg().id && O_SIZE_64 == opd.GetSize();
                    }

                    return false;
                }
            };


            template< PhysicalRegID id, Access access >
            struct _rv_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg())
                    {
                        return id == opd.GetReg().id && O_SIZE_8 != opd.GetSize();
                    }

                    return false;
                }
            };

            template< PhysicalRegID id, Access access >
            struct _ry_
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    if (opd.IsGpReg() && id == opd.GetReg().id)
                    {
                        switch (opd.GetSize())
                        {
                        case O_SIZE_32:
                        case O_SIZE_64:
                            return true;
                        }
                    }

                    return false;
                }
            };

            template< size_t index, PhysicalRegID regid, Access access = RW > struct DummyRb
            {
            };

            template< size_t index, PhysicalRegID regid, Access access = RW > struct DummyRw
            {
            };

            template< size_t index, PhysicalRegID regid, Access access = RW > struct DummyRd
            {
            };

            template< size_t index, PhysicalRegID regid, Access access = RW > struct DummyRq
            {
            };

            /////////////

            struct None
            {
                static bool Matches(Instr & instr, size_t index)
                {
                    auto & opd = instr.GetOpd(index);
                    return opd.IsNone();
                }
            };

            //////////////////////////////////////////////////////////////////
            // Opcode Extensions for One- and Two-byte Opcodes by Group Number

            template< size_t code >
            struct Group1 /* 80-83 */
            {
            };
            template< size_t code >
            struct Group1A /* 8F */
            {
            };
            template< size_t code >
            struct Group2 /* C0-C1 reg, imm / D0,D1 reg, 1 / D2-D3 reg, CL */
            {
            };
            template< size_t code >
            struct Group3 /* F6-F7 */
            {
            };
            template< size_t code >
            struct Group4 /* FE */
            {
            };
            template< size_t code >
            struct Group5 /* FF */
            {
            };
            template< size_t code >
            struct Group6 /* 0F 00 */
            {
            };
            template< size_t code >
            struct Group7 /* 0F 01 */
            {
            };
            template< size_t code >
            struct Group8 /* 0F BA */
            {
            };
            template< size_t code >
            struct Group9 /* 0F C7 */
            {
            };
            template< size_t code >
            struct Group10 /* 0F B9 */
            {
            };
            template< size_t code >
            struct Group11 /* C6-C7 */
            {
            };
            template< size_t code >
            struct Group12 /* 0F 71 */
            {
            };
            template< size_t code >
            struct Group13 /* 0F 72 */
            {
            };
            template< size_t code >
            struct Group14 /* 0F 73 */
            {
            };
            template< size_t code >
            struct Group15 /* 0F AE */
            {
            };
            template< size_t code >
            struct Group16 /* 0F 18 */
            {
            };
            template< size_t code >
            struct Group17 /* VEX.0F 73 F3 */
            {
            };

            /////////////

            template< size_t flags >
            struct EncodingFlags
            {
            };

            struct OSb; // Operand Size prefix : byte (8-bit)
            struct OSw; // Operand Size prefix : word (16-bit)
            struct OSd; // Operand Size prefix : dword (32-bit)
            struct OSq; // Operand Size prefix : qword (64-bit)

            struct ASw; // Address Size prefix : word (16-bit)
            struct ASd; // Address Size prefix : dword (32-bit)
            struct ASq; // Address Size prefix : qword (64-bit)

            struct i64; // Invalid in 64-bit mode
            struct o64; // Only in 64-bit mode

            /////////////

            template< Access a0, Access a1                       > struct Bd_Ed        : Match < _Bd_ < a0 >, _Ed_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Bq_Eq        : Match < _Bq_ < a0 >, _Eq_ < a1 >,                                       None > {};
            
            template< Access a0, Access a1, Access a2, Access a3 > struct Bd_Gd_Gd_Ed  : Match < _Bd_ < a0 >, _Gd_ < a1 >, _Gd_ < a2 >, _Ed_ < a3 >,             None > {};
            template< Access a0, Access a1, Access a2, Access a3 > struct Bq_Gq_Gq_Eq  : Match < _Bq_ < a0 >, _Gq_ < a1 >, _Gq_ < a2 >, _Eq_ < a3 >,             None > {};

            template< Access a0                                  > struct Eb           : Match < _Eb_ < a0 >,                                                    None > {};
            template< Access a0, Access a1                       > struct Eb_Gb        : Match < _Eb_ < a0 >, _Gb_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Eb_Ib        : Match < _Eb_ < a0 >, _Ib_,                                              None > {};

            template< Access a0                                  > struct Ew           : Match < _Ew_ < a0 >,                                                    None > {};
            template< Access a0, Access a1                       > struct Ew_Gw        : Match < _Ew_ < a0 >, _Gw_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Ew_Ib        : Match < _Ew_ < a0 >, _Ib_,                                              None > {};
            template< Access a0                                  > struct Ew_Iw        : Match < _Ew_ < a0 >, _Iw_,                                              None > {};

            template< Access a0                                  > struct Ed           : Match < _Ed_ < a0 >,                                                    None > {};
            template< Access a0, Access a1                       > struct Ed_Gd        : Match < _Ed_ < a0 >, _Gd_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Ed_Ib        : Match < _Ed_ < a0 >, _Ib_,                                              None > {};
            template< Access a0                                  > struct Ed_Id        : Match < _Ed_ < a0 >, _Id_,                                              None > {};

            template< Access a0                                  > struct Eq           : Match < _Eq_ < a0 >,                                                    None > {};
            template< Access a0, Access a1                       > struct Eq_Gq        : Match < _Eq_ < a0 >, _Gq_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Eq_Ib        : Match < _Eq_ < a0 >, _Ib_,                                              None > {};
            template< Access a0                                  > struct Eq_Id        : Match < _Eq_ < a0 >, _Id_,                                              None > {};

            template< Access a0                                  > struct Gb           : Match < _Gb_ < a0 >,                                                    None > {};
            template< Access a0, Access a1                       > struct Gb_Eb        : Match < _Gb_ < a0 >, _Eb_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gb_Gw        : Match < _Gb_ < a0 >, _Gw_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Gb_Ib        : Match < _Gb_ < a0 >, _Ib_,                                              None > {};

            template< Access a0                                  > struct Gw           : Match < _Gw_ < a0 >,                                                    None > {};
            template< Access a0, Access a1                       > struct Gw_Eb        : Match < _Gw_ < a0 >, _Eb_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gw_Ew        : Match < _Gw_ < a0 >, _Ew_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gw_Ew_Ib     : Match < _Gw_ < a0 >, _Ew_ < a1 >, _Ib_,                                 None > {};
            template< Access a0, Access a1                       > struct Gw_Ew_Iw     : Match < _Gw_ < a0 >, _Ew_ < a1 >, _Iw_,                                 None > {};
            template< Access a0, Access a1                       > struct Gw_Gb        : Match < _Gw_ < a0 >, _Gb_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gw_Gw        : Match < _Gw_ < a0 >, _Gw_ < a1 >,                                       None > {};
            template< Access a0, Access a1, Access a2            > struct Gw_Gw_Ew     : Match < _Gw_ < a0 >, _Gw_ < a1 >, _Ew_< a2 >,                           None > {};
            template< Access a0, Access a1                       > struct Gw_Gd        : Match < _Gw_ < a0 >, _Gd_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gw_Md        : Match < _Gw_ < a0 >, _Md_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Gw_Ib        : Match < _Gw_ < a0 >, _Ib_,                                              None > {};
            template< Access a0                                  > struct Gw_Iw_Ib     : Match < _Gw_ < a0 >, _Iw_, _Ib_,                                        None > {};
            template< Access a0, Access a1                       > struct Gw_Xb        : Match < _Gw_ < a0 >, _Xb_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gw_Xw        : Match < _Gw_ < a0 >, _Xw_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gw_Xd        : Match < _Gw_ < a0 >, _Xd_ < a1 >,                                       None > {};

            template< Access a0                                  > struct Gd           : Match < _Gd_ < a0 >,                                                    None > {};
            template< Access a0, Access a1, Access a2            > struct Gd_Bd_Ed     : Match < _Gd_ < a0 >, _Bd_ < a1 >, _Ed_ < a2 >,                          None > {};
            template< Access a0, Access a1, Access a2            > struct Gd_Ed_Bd     : Match < _Gd_ < a0 >, _Ed_ < a1 >, _Bd_ < a2 >,                          None > {};
            template< Access a0, Access a1                       > struct Gd_Ed        : Match < _Gd_ < a0 >, _Ed_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gd_Ed_Ib     : Match < _Gd_ < a0 >, _Ed_ < a1 >, _Ib_,                                 None > {};
            template< Access a0, Access a1                       > struct Gd_Ed_Id     : Match < _Gd_ < a0 >, _Ed_ < a1 >, _Id_,                                 None > {};
            template< Access a0, Access a1                       > struct Gd_Gw        : Match < _Gd_ < a0 >, _Gw_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gd_Gd        : Match < _Gd_ < a0 >, _Gd_ < a1 >,                                       None > {};
            template< Access a0, Access a1, Access a2            > struct Gd_Gd_Ed     : Match < _Gd_ < a0 >, _Gd_ < a1 >, _Ed_< a2 >,                           None > {};
            template< Access a0, Access a1                       > struct Gd_Mq        : Match < _Gd_ < a0 >, _Mq_ < a1 >,                                       None > {};
            template< Access a0                                  > struct Gd_Ib        : Match < _Gd_ < a0 >, _Ib_,                                              None > {};
            template< Access a0                                  > struct Gd_Iw_Ib     : Match < _Gd_ < a0 >, _Iw_, _Ib_,                                        None > {};
            template< Access a0, Access a1, Access a2            > struct Gdd_Mq_Gdd   : Match < _Gd_ < a0 >, _Gd_ < a0 >, _Mq_< a1 >, _Gd_ < a2 >, _Gd_ < a2 >, None > {};

            template< Access a0                                  > struct Gq           : Match < _Gq_ < a0 >,                                                    None > {};
            template< Access a0, Access a1, Access a2            > struct Gq_Bq_Eq     : Match < _Gq_ < a0 >, _Bq_ < a1 >, _Eq_ < a2 >,                          None > {};
            template< Access a0, Access a1, Access a2            > struct Gq_Eq_Bq     : Match < _Gq_ < a0 >, _Eq_ < a1 >, _Bq_ < a2 >,                          None > {};
            template< Access a0, Access a1                       > struct Gq_Eq        : Match < _Gq_ < a0 >, _Eq_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Gq_Eq_Ib     : Match < _Gq_ < a0 >, _Eq_ < a1 >, _Ib_,                                 None > {};
            template< Access a0, Access a1                       > struct Gq_Eq_Id     : Match < _Gq_ < a0 >, _Eq_ < a1 >, _Id_,                                 None > {};
            template< Access a0, Access a1                       > struct Gq_Gq        : Match < _Gq_ < a0 >, _Gq_ < a1 >,                                       None > {};
            template< Access a0, Access a1, Access a2            > struct Gq_Gq_Eq     : Match < _Gq_ < a0 >, _Gq_ < a1 >, _Eq_< a2 >,                           None > {};
            template< Access a0                                  > struct Gq_Ib        : Match < _Gq_ < a0 >, _Ib_,                                              None > {};
            template< Access a0                                  > struct Gq_Iw_Ib     : Match < _Gq_ < a0 >, _Iw_, _Ib_,                                        None > {};
            template< Access a0, Access a1, Access a2            > struct Gqq_Mo_Gqq   : Match < _Gq_ < a0 >, _Gq_ < a0 >, _Mo_< a1 >, _Gq_ < a2 >, _Gq_ < a2 >, None > {};

            /**/                                                   struct Ib           : Match < _Ib_,                                                           None > {};
            template< Access a0                                  > struct Ib_Gb        : Match < _Ib_, _Gb_ < a0 >,                                              None > {};
            template< Access a0                                  > struct Ib_Gw        : Match < _Ib_, _Gw_ < a0 >,                                              None > {};
            template< Access a0                                  > struct Ib_Gd        : Match < _Ib_, _Gd_ < a0 >,                                              None > {};

            /**/                                                   struct Jb           : Match < _Jb_,                                                           None > {};
            /**/                                                   struct Jw           : Match < _Jw_,                                                           None > {};
            /**/                                                   struct Jd           : Match < _Jd_,                                                           None > {};

            template< Access a0                                  > struct Mb           : Match < _Mb_ < a0 >,                                                    None > {};
            template< Access a0                                  > struct Mw           : Match < _Mw_ < a0 >,                                                    None > {};
            template< Access a0                                  > struct Md           : Match < _Md_ < a0 >,                                                    None > {};
            template< Access a0                                  > struct Mq           : Match < _Mq_ < a0 >,                                                    None > {};

            template< Access a0, Access a1                       > struct Xb_Yb        : Match < _Xb_ < a0 >, _Yb_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Xw_Yw        : Match < _Xw_ < a0 >, _Yw_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Xd_Yd        : Match < _Xd_ < a0 >, _Yd_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Xq_Yq        : Match < _Xq_ < a0 >, _Yq_ < a1 >,                                       None > {};

            template< Access a0, Access a1                       > struct Yb_Gw        : Match < _Yb_ < a0 >, _Gw_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Yw_Gw        : Match < _Yw_ < a0 >, _Gw_ < a1 >,                                       None > {};
            template< Access a0, Access a1                       > struct Yd_Gw        : Match < _Yd_ < a0 >, _Gw_ < a1 >,                                       None > {};

            template< Access a0                                  > struct Zw           : Match < _Zw_ < a0 >,                                                    None > {};
            template< Access a0                                  > struct Zd           : Match < _Zd_ < a0 >,                                                    None > {};
            template< Access a0                                  > struct Zq           : Match < _Zq_ < a0 >,                                                    None > {};

            template< Access a0                                  > struct AL_Ib        : Match < _rb_ < AL, a0 >, _Ib_,                                          None > {};
            template< Access a0                                  > struct AX_Iw        : Match < _rw_ < AX, a0 >, _Iw_,                                          None > {};
            template< Access a0                                  > struct EAX_Id       : Match < _rd_ < EAX, a0 >, _Id_,                                         None > {};
            template< Access a0                                  > struct RAX_Id       : Match < _rq_ < RAX, a0 >, _Id_,                                         None > {};

            /////////////

            template< Access a > detail::Opd AlterAccess(detail::Opd const & opd)
            {
                return a == R ? detail::R(opd) : a == W ? detail::W(opd) : detail::RW(opd);
            }
        }
    }
}
#endif // jitasm_x86_h__