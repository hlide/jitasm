#pragma once
#ifndef jitasm_Backend_x86_64_h__
#define jitasm_Backend_x86_64_h__
#include "jitasm.x86_64.h"
#include "jitasm.Backend.x86.h"
namespace jitasm
{
    namespace x86_64
    {
        struct Backend : jitasm::x86::Backend
        {
            Backend(void * buffaddr = nullptr, size_t buffsize = 0) : jitasm::x86::Backend(true, buffaddr, buffsize)
            {
            }
        };
    }
}
#endif // jitasm_Backend_x86_64_h__