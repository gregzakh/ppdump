#ifndef _HELPERS_H_
#define _HELPERS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define _PRINT_LOG(stream, fmt, ...) do { \
    fprintf(stream, fmt, ##__VA_ARGS__);  \
    fprintf(stream, "\r\n");              \
} while(0)

#define log(fmt, ...) _PRINT_LOG(stdout, fmt, ##__VA_ARGS__)
#define err(fmt, ...) _PRINT_LOG(stderr, fmt, ##__VA_ARGS__)

#define separator "------------------------------------------------------------"
#define space "    "

#define add(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
void hexdump(const uint8_t *p, size_t n, const char *prefix) {
    for (size_t i = 0; i < n; i+= 16) {
        add("%s%08llX  ", prefix, i);
        size_t m = (n - i < 16) ? n - i : 16;
        for (size_t j = 0; j < 16; j++) {
            if (j < m)
                add("%02X ", p[i + j]);
            else
                add("   ");
            
            if (j == 7)
                add(" ");
        }
        add(" |");
        for (size_t j = 0; j < m; j++) {
            uint8_t c = p[i + j];
            add("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        add("|\n");
    }
}

char *utf16le_to_utf8(const uint8_t *p, size_t bytes, size_t *out_len) {
    if (!p || bytes == 0 || (bytes % 2) != 0)
        return NULL;
    
    size_t n = bytes / 2;
    char *out = malloc(n * 4 + 1);
    if (!out)
        return NULL;

    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        uint16_t wc = (uint16_t)(p[2 * i] | (p[2 * i + 1] << 8));
        if (wc == 0)
            break;
        
        if (wc < 0x80) {
            out[j++] = (char)wc;
        } else if (wc < 0x800) {
            out[j++] = (char)(0xC0 | (wc >> 6));
            out[j++] = (char)(0x80 | (wc & 0x3F));
        } else if (wc >= 0xD800 && wc <= 0xDFFF) {
            out[j++] = '?';
        } else {
            out[j++] = (char)(0xE0 | (wc >> 12));
            out[j++] = (char)(0x80 | ((wc >> 6) & 0x3F));
            out[j++] = (char)(0x80 | (wc & 0x3F));
        }
    }
    out[j] = '\0';
    if (out_len)
        *out_len = j;
    
    return out;
}

int looks_like_utf16_name(const uint8_t *p, size_t bytes) {
    if (bytes < 2 || (bytes % 2))
        return 0;
    
    size_t n = bytes / 2;
    int32_t printable = 0;
    for (size_t i = 0; i < n; i++) {
        uint16_t wc = (uint16_t)(p[2 * i] | (p[2 * i + 1] << 8));
        if (wc == 0)
            return printable > 0;
        
        if (wc >= 0x20 && wc < 0x7F) {
            printable++;
            continue;
        }

        if (wc == '\t' || wc == '\n' || wc == '\r') {
            printable++;
            continue;
        }

        return 0;
    }

    return printable > 0;
}

#endif