#pragma once
#include <intrin.h>

#if defined(_MSC_VER)
#define SK_CODE_SEG(name) __pragma(code_seg(name))
#define SK_END_SEG __pragma(code_seg())
#define SK_NOINLINE __declspec(noinline)
#else
#define SK_CODE_SEG(name)
#define SK_END_SEG
#define SK_NOINLINE
#endif

#define SK_UNIQUE_SEED (__COUNTER__ ^ __LINE__ ^ 0x7F4A7C15)

#define SK_JUNK_BODY(seed)                \
    do {                                  \
        volatile unsigned int a = seed;   \
        volatile unsigned int b = seed >> 1; \
        volatile unsigned int c = 0;      \
        for (int i = 0; i < 7; ++i) {     \
            a ^= (b + i);                 \
            b += (a ^ seed);              \
            c += (a & b) ^ (b | a);       \
        }                                 \
        if ((c ^ seed) & 1) {             \
            c = (c << 3) | (c >> 2);      \
        } else {                          \
            c = (c >> 1) ^ (a + b);       \
        }                                 \
        _ReadWriteBarrier();              \
    } while (0)

#define skVMP0()      \
    SK_CODE_SEG(".vmp0") \
    SK_NOINLINE { SK_JUNK_BODY(SK_UNIQUE_SEED); } \
    SK_END_SEG

#define skVMP1()      \
    SK_CODE_SEG(".vmp1") \
    SK_NOINLINE { SK_JUNK_BODY(SK_UNIQUE_SEED); } \
    SK_END_SEG

#define skENIGMA1()   \
    SK_CODE_SEG(".enigma1") \
    SK_NOINLINE { SK_JUNK_BODY(SK_UNIQUE_SEED); } \
    SK_END_SEG

#define skENIGMA2()   \
    SK_CODE_SEG(".enigma2") \
    SK_NOINLINE { SK_JUNK_BODY(SK_UNIQUE_SEED); } \
    SK_END_SEG

#define skTHEMIDA()   \
    SK_CODE_SEG(".themida") \
    SK_NOINLINE { SK_JUNK_BODY(SK_UNIQUE_SEED); } \
    SK_END_SEG
