#pragma once
#ifndef jitasm_h__
#define jitasm_h__

#define JITASM_TEST

#if defined(_WIN32)
#define JITASM_WIN		// Windows
#endif

#if (defined(_WIN64) && (defined(_M_AMD64) || defined(_M_X64))) || defined(__x86_64__)
#define JITASM_X64
#endif

#if defined(__GNUC__)
#define JITASM_GCC
#endif

#if !defined(JITASM_MMINTRIN)
#if !defined(__GNUC__) || defined(__MMX__)
#define JITASM_MMINTRIN 1
#else
#define JITASM_MMINTRIN 0
#endif
#endif
#if !defined(JITASM_XMMINTRIN)
#if !defined(__GNUC__) || defined(__SSE__)
#define JITASM_XMMINTRIN 1
#else
#define JITASM_XMMINTRIN 0
#endif
#endif
#if !defined(JITASM_EMMINTRIN)
#if !defined(__GNUC__) || defined(__SSE2__)
#define JITASM_EMMINTRIN 1
#else
#define JITASM_EMMINTRIN 0
#endif
#endif


#include <string>
#include <deque>
#include <vector>
#include <map>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <string.h>

#if defined(JITASM_WIN)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#endif

#if JITASM_MMINTRIN
#include <mmintrin.h>
#endif
#if JITASM_XMMINTRIN
#include <xmmintrin.h>
#endif
#if JITASM_EMMINTRIN
#include <emmintrin.h>
#endif

#if _MSC_VER >= 1400	// VC8 or later
#include <intrin.h>
#endif

#if defined(JITASM_GCC)
#define JITASM_ATTRIBUTE_WEAK __attribute__((weak))
#elif defined(_MSC_VER)
#define JITASM_ATTRIBUTE_WEAK __declspec(selectany)
#else
#define JITASM_ATTRIBUTE_WEAK
#endif

#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4127 )	// conditional expression is constant.
#pragma warning( disable : 4201 )	// nonstandard extension used : nameless struct/union
#endif

#ifdef ASSERT
#define JITASM_ASSERT ASSERT
#else
#include <assert.h>
//#define JITASM_ASSERT assert
#define JITASM_ASSERT(x) x
#endif

//#define JITASM_DEBUG_DUMP
#ifdef JITASM_DEBUG_DUMP
#include <stdio.h>
#if defined(JITASM_GCC)
#define JITASM_TRACE	printf
#else
#define JITASM_TRACE	jitasm::detail::Trace
#endif
#elif defined(JITASM_GCC)
#define JITASM_TRACE(...)	((void)0)
#else
#define JITASM_TRACE	__noop
#endif

#include <stdint.h>
#include <mutex>

namespace jitasm
{
    typedef int8_t				sint8;
    typedef int16_t				sint16;
    typedef int32_t				sint32;
    typedef int64_t				sint64;
    typedef uint8_t				uint8;
    typedef uint16_t			uint16;
    typedef uint32_t			uint32;
    typedef uint64_t			uint64;

    template< typename T > inline void avoid_unused_warn(T const &) {}

    namespace detail
    {
        inline void * aligned_malloc(size_t size, size_t alignment)
        {
#ifdef __MINGW32__
            return __mingw_aligned_malloc(size, alignment);
#elif defined(_MSC_VER)
            return _aligned_malloc(size, alignment);
#else
            void * p;
            int ret = posix_memalign(&p, alignment, size);
            return (ret == 0) ? p : 0;
#endif
        }

        inline void aligned_free(void * p)
        {
#ifdef __MINGW32__
            __mingw_aligned_free(p);
#elif defined(_MSC_VER)
            _aligned_free(p);
#else
            free(p);
#endif
        }

        /// Counting 1-Bits
        inline uint32 count_1_bits(uint32 x)
        {
            x = x - ((x >> 1) & 0x55555555);
            x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
            x = (x + (x >> 4)) & 0x0F0F0F0F;
            x = x + (x >> 8);
            x = x + (x >> 16);
            return x & 0x0000003F;
        }

        /// The bit position of the first bit 1.
        inline uint32 bit_scan_forward(uint32 x)
        {
#if defined(JITASM_GCC)
            return __builtin_ctz(x);
#else
            unsigned long index;
            _BitScanForward(&index, x);
            return index;
#endif
        }

        /// The bit position of the last bit 1.
        inline uint32 bit_scan_reverse(uint32 x)
        {
#if defined(JITASM_GCC)
            return 31 - __builtin_clz(x);
#else
            unsigned long index;
            _BitScanReverse(&index, x);
            return index;
#endif
        }

        /// Prior iterator
        template< class It > It prior(It const & it)
        {
            It i = it;
            return --i;
        }

        /// Next iterator
        template< class It > It next(It const & it)
        {
            It i = it;
            return ++i;
        }

        /// Iterator range
        template< class T, class It = typename T::iterator > struct Range : std::pair < It, It >
        {
            typedef It Iterator;
            Range() : std::pair< It, It >() {}
            Range(It const & f, It const & s) : std::pair< It, It >(f, s) {}
            Range(T & container) : std::pair< It, It >(container.begin(), container.end()) {}
            bool empty() const { return this->first == this->second; }
            size_t size() const { return std::distance(this->first, this->second); }
        };

        /// Const iterator range
        template< class T > struct ConstRange : Range < T, typename T::const_iterator >
        {
            ConstRange() : Range< T, typename T::const_iterator >() {}
            ConstRange(typename T::const_iterator const & f, typename T::const_iterator const & s) : Range< T, typename T::const_iterator >(f, s) {}
            ConstRange(T const & container) : Range< T, typename T::const_iterator >(container.begin(), container.end()) {}
        };

        inline void append_num(std::string & str, size_t num)
        {
            if (num >= 10)
            {
                append_num(str, num / 10);
            }
            str.append(1, static_cast<char>('0' + num % 10));
        }

#if defined(JITASM_DEBUG_DUMP) && defined(JITASM_WIN)
        /// Debug trace
        inline void Trace(const char *format, ...)
        {
            char szBuf[256];
            va_list args;
            va_start(args, format);
#if _MSC_VER >= 1400	// VC8 or later
            _vsnprintf_s(szBuf, sizeof(szBuf) / sizeof(char), format, args);
#else
            vsnprintf(szBuf, sizeof(szBuf) / sizeof(char), format, args);
#endif
            va_end(args);
            ::OutputDebugStringA(szBuf);
        }
#endif
    }
}

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

#endif // jitasm_h__

