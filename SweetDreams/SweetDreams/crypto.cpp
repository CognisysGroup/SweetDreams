#include "commun.h"

void xor_aa(BYTE* input, size_t length) {

    for (int i = 0; i < length; i++) {
        input[i] = input[i] ^ 0xaa;
    }

}

void xor_stack(void* stack_top, void* stack_base) {
    unsigned char* top = (unsigned char*)stack_top;
    unsigned char* base = (unsigned char*)stack_base;

    for (unsigned char* p = top; p < base; ++p) {
        *p ^= 0xAA;
    }
}