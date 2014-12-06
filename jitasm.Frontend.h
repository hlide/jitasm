#pragma once
#ifndef jitasm_Frontend_h__
#define jitasm_Frontend_h__
#include "jitasm.h"
#include "jitasm.CodeBuffer.h"
namespace jitasm
{
    class Frontend
    {
    protected:
        virtual ~Frontend()
        {
        }

        virtual void Assemble() = 0;
    };

    template < typename Derived > struct Frontend$CRTP : Frontend /* using Curiously Recurring Template Pattern */
	{
        Derived & derived()
        {
            return *static_cast<Derived *>(this);
        }

        Derived const & derived() const
        {
            return *static_cast<Derived const *>(this);
        }

        struct Label
		{
			sint32      key;
			size_t		instr;
			explicit Label(sint32 key) : key(key), instr(0) {}
		};
		typedef std::deque< Label > LabelList;

		bool         assembled_;
		LabelList	 labels_;

		Frontend$CRTP() : assembled_(false)
        {
        }

		void * GetCodePointer()
		{
			if (!assembled_)
			{
				Assemble();
			}
			return derived().GetBufferPointer();
		}

        size_t GetCodeSize()
        {
            return derived().GetBufferSize();
        }

        size_t NewLabelID(sint32 label_key)
		{
			labels_.push_back(Label(label_key));
			return labels_.size() - 1;
		}

		size_t CheckLabelID(sint32 label_key)
		{
			for (size_t i = 0; i < labels_.size(); i++)
			{
				if (labels_[i].key == label_key)
				{
					return i;
				}
			}
			return (size_t)-1;
		}

		size_t GetLabelID(sint32 label_key)
		{
			for (auto const & label : labels)
			{
				if (label.key == label_key)
				{
					return i;
				}
			}
			return NewLabelID(label_key);
		}

		void SetLabelID(size_t label_id)
		{
			labels_[label_id].instr = instrs_.size();
		}

		void L(sint32 label_key)
		{
			SetLabelID(GetLabelID(label_key));
		}
	};
}
#endif // jitasm_Frontend_h__
