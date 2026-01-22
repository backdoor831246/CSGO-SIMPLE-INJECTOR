#pragma once
#ifndef PROTECTIONS_H
#define PROTECTIONS_H

#include <windows.h>
#include <iostream>

#define FAKE_JUNK do {             \
    volatile int a = 123;          \
    volatile int b = 456;          \
    volatile int c = 0;            \
    for (int i = 0; i < 10; ++i) { \
        a ^= b;                    \
        b += i;                    \
        c += (a & b) ^ (b | a);    \
    }                              \
    if ((c % 3) == 0) {            \
        c = (c << 2) | (c >> 3);   \
    } else {                       \
        c = (c >> 1) ^ (a + b);    \
    }                              \
    for (int i = 0; i < 5; ++i) {  \
        __nop;                     \
    }                              \
} while(0)

#pragma code_seg(".vmp0")
__declspec(noinline) inline void VMP0() {
    FAKE_JUNK;
}
#pragma code_seg()

#pragma code_seg(".vmp1")
__declspec(noinline) inline void VMP1() {
    FAKE_JUNK;
}
#pragma code_seg()

#pragma code_seg(".enigma1")
__declspec(noinline) inline void ENIGMA1() {
    FAKE_JUNK;
}
#pragma code_seg()

#pragma code_seg(".enigma2")
__declspec(noinline) inline void ENIGMA2() {
    FAKE_JUNK;
}
#pragma code_seg()

#pragma code_seg(".themida")
__declspec(noinline) inline void THEMIDA() {
    FAKE_JUNK;
}
#pragma code_seg()

#endif 
