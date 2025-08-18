#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "obfusheader.h"
#undef for

#define FLAG_LEN 40
#define FLAG_TEMPLATE "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"


extern "C" {

unsigned char flag[104] = { 0 };

__attribute__((constructor)) static void con() {
    CALL(&srand, OBF(0x48691412));
    CALL(&puts, OBF("Hello, CTFer!"));
}

NOINLINE size_t simple_strlen(const char* str) {
    const char* s;
    for (s = str; *s; ++s);
    return (s - str);
}

NOINLINE void rand_xor(unsigned short* flag, size_t len) {
    for (int i = 0; i < len / 2; i++) {
        flag[i] ^= rand() & 0xFFFF;
    }
}

NOINLINE void obfuscate_bytes(unsigned char* flag, size_t len) {
    for (int i = 0; i < len; i++) {
        unsigned char raw = flag[i];
        INDIRECT_BRANCH;
        unsigned char low_nibble = raw << 4;
        INDIRECT_BRANCH;
        unsigned char high_nibble = raw >> 4;
        INDIRECT_BRANCH;
        flag[i] = low_nibble | high_nibble;
        INDIRECT_BRANCH;
    }
    INDIRECT_BRANCH;
    for (int i = 0; i < len; i++) {
        INDIRECT_BRANCH;
        flag[i] ^= 0xFF;
        INDIRECT_BRANCH;
    }
    int tip[] = {
        'E', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'o', 'n', ' ',
        'd', 'o', 'n', 'e', ',', ' ', 't', 'i', 'm', 'e', ' ',
        't', 'o', ' ', 'c', 'o', 'm', 'p', 'a', 'r', 'e', '!', '\n', 
    };
    for (int i = 0; i < sizeof(tip) / sizeof(int); i++) {
        putchar(tip[i]);
    }
}

NOINLINE void process(unsigned char* flag) {
    INDIRECT_BRANCH;
    size_t len = CALL(&simple_strlen, (const char*)flag);
    if (len < OBF(FLAG_LEN)) {
        INDIRECT_BRANCH;
        CALL(&puts, OBF("Your flag is too short!"));
        return;
    }
    if (len > OBF(FLAG_LEN)) {
        INDIRECT_BRANCH;
        CALL(&puts, OBF("Your flag is too long!"));
        return;
    }
    INDIRECT_BRANCH;
    CALL(&rand_xor, (unsigned short*)flag, len);
    INDIRECT_BRANCH;
    CALL(&obfuscate_bytes, flag, len);
    INDIRECT_BRANCH;
    if (CALL(&memcmp, flag, OBF(FLAG_TEMPLATE), OBF(FLAG_LEN)) != 0) {
        INDIRECT_BRANCH;
        CALL(&puts, OBF("Wrong flag!"));
    } else {
        INDIRECT_BRANCH;
        CALL(&puts, OBF("Correct flag!"));
    }
}

int main() {
    CALL(&printf, "Please enter the flag: ");
    CALL(&scanf, "%100s", flag);
    WATERMARK(
        "    __    ______    __________________",
        "   / /   /  _/ /   / ____/_  __/ ____/",
        "  / /    / // /   / /     / / / /_    ",
        " / /____/ // /___/ /___  / / / __/    ",
        "/_____/___/_____/_____/ /_/ /_/       ",
    );
    INDIRECT_BRANCH;
    CALL(&process, flag);
    return 0;
}

} // extern "C"
