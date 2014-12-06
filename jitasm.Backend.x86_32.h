#pragma once
#ifndef jitasm_Backend_x86_32_h__
#define jitasm_Backend_x86_32_h__
#include "jitasm.x86_32.h"
#include "jitasm.Backend.x86.h"
namespace jitasm
{
    namespace x86_32
    {
        struct Backend : jitasm::x86::Backend
        {
            Backend(void * buffaddr = nullptr, size_t buffsize = 0) : jitasm::x86::Backend(false, buffaddr, buffsize)
            {
            }
        };
    }
}
#endif // jitasm_Backend_x86_32_h__