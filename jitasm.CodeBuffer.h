#pragma once
#ifndef jitasm_CodeBuffer_h__
#define jitasm_CodeBuffer_h__
#include "jitasm.h"
namespace jitasm
{
    template < typename Derived > class CodeBuffer$CRTP /* using Curiously Recurring Template Pattern */
    {
    protected:
        void  *	buffaddr_;
        size_t	codesize_;
        size_t	buffsize_;

        Derived & derived()
        {
            return *static_cast<Derived *>(this);
        }

        Derived const & derived() const
        {
            return *static_cast<Derived const *>(this);
        }

    public:
        CodeBuffer$CRTP() : buffaddr_(nullptr), codesize_(0), buffsize_(0)
        {
        }
        ~CodeBuffer$CRTP()
        {
            ResetBuffer(0);
        }

        void * GetBufferPointer() const
        {
            return buffaddr_;
        }
        size_t GetBufferCapacity() const
        {
            return buffsize_;
        }
        size_t GetBufferSize() const
        {
            return codesize_;
        }

        bool ResetBuffer(size_t codesize)
        {
            bool result = true;
            if (buffaddr_)
            {
                result = result || derived().FreeBuffer();
                if (result)
                {
                    buffaddr_ = nullptr;
                    codesize_ = 0;
                    buffsize_ = 0;
                }
            }
            if (result && codesize)
            {
                result = result && derived().AllocateBuffer(codesize);
                if (result)
                {
                    codesize_ = codesize;
                }
            }
            return result;
        }
    };
}
#endif // jitasm_CodeBuffer_h__
