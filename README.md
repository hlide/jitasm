jitasm
======

JIT Assembler Library for multiple ISAs. For now, only x86.  

### Goal

To emit assembly code to create run-time functions dynamically with the optional ability to use virtual (symbolic or memory-mapped) registers to let jitasm compiler allocates physical registers itself using a linear scan register allocation.

### Features [*in progress*]

- *Header file only*
- Support for 32-bit and 64-bit x86, *mmx, sse, sse2, sse3, ssse3, sse4.1, sse4.2, avx, avx2, avx3, fma, xop, fma4*
- *Register allocation*
- Support for Windows, *Linux, FreeBSD, Mac*

### Status

-=[ WORK IN PROGRESS ]=-

### Remark

Everything may undergo change

### X86 Manuals

Finding out some text or xml files to describe the opcode maps of all the x86 instructions up to AVX3 is almost impossible. So far there are only two sources :
- xml file : http://ref.x86asm.net/x86reference.xml
- txt file : http://lxr.free-electrons.com/source/arch/x86/lib/x86-opcode-map.txt?v=3.18

As for web links to manuals, I found out three interesting links :
- http://www.sandpile.org/ : the most complete one since it contains AVX3 instructions. I am also attempting to put the opcode maps into one page and perhaps I will use it to extract instructions details to make a source file to describe all x86 isntructions I need.
- http://www.felixcloutier.com/x86/ : this one is normally auto-generated from Intel manuals but it lacks opcode maps and AVX3 instructions.
- http://ref.x86asm.net : this one is probably the most informative except that it does not contain AVX+ instructions. 

There are of course PDF manuals of Intel and AMD - but you know, they are not that easy to extract informations on instructions (some instructions are not extracted correctly in http://www.felixcloutier.com/x86/). 
