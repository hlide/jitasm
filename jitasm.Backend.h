#include "jitasm.h"

namespace jitasm
{
    template < typename Derived > struct Backend$CRTP
    {
        uint8                         * buffaddr_;
        size_t	                        buffsize_;
        size_t	                        size_;
        std::multimap< size_t, uint64 > bookmarks_;

        Backend$CRTP(void * buffaddr = nullptr, size_t buffsize = 0)
            : buffaddr_((uint8 *)buffaddr), buffsize_(buffsize), size_(0)
        {
        }

        std::vector< uint64 > GetBookmarks(size_t offset)
        {
            std::vector< uint64 > sources;
            auto r = bookmarks_.equal_range(offset);
            for (auto i = r.first; i != r.second; ++i)
            {
                sources.push_back(i->second);
            }
            return sources;
        }

        void AddBookmark(size_t offset, uint64 bookmark)
        {
            bookmarks_.insert(std::make_pair(offset, bookmark));
        }

        size_t GetSize() const
        {
            return size_;
        }

        void PutBytes(void * p, size_t n)
        {
            uint8 * pb = (uint8 *)p;
            if (buffaddr_)
            {
                while (n--) buffaddr_[size_++] = *pb++;
            }
            else
            {
                size_ += n;
            }
        }

        void db(uint64 b)
        {
            PutBytes(&b, 1);
        }
        
        void dw(uint64 w)
        {
            PutBytes(&w, 2);
        }
        
        void dd(uint64 d)
        {
            PutBytes(&d, 4);
        }
        
        void dq(uint64 q)
        {
            PutBytes(&q, 8);
        }
    };
}