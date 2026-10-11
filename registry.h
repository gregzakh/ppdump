#ifndef _REGISTRY_H_
#define _REGISTRY_H_

#include "helpers.h"
#include <windows.h>
#include <string.h>

#pragma comment (lib, "advapi32")

#define ProductPolicy L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
#define TargetValue L"ProductPolicy"

struct reg_value {
    int32_t  status;
    uint32_t type;
    uint32_t size;
    uint8_t  *buffer;
};

struct reg_value reg_read(void) {
    HKEY key = NULL;
    LSTATUS result;
    uint8_t *tmp = NULL;
    struct reg_value val = { 0 };

    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ProductPolicy, 0, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) {
        val.status = result;
        goto cleanup;
    }

    result = RegQueryValueExW(key, TargetValue, NULL, (LPDWORD)&val.type, NULL, (LPDWORD)&val.size);
    if (result != ERROR_MORE_DATA && result != ERROR_SUCCESS) {
        val.status = result;
        goto cleanup;
    }

    if (val.size == 0) {
        val.status = ERROR_SUCCESS;
        goto cleanup;
    }

    tmp = (uint8_t*)malloc(val.size);
    if (!tmp) {
        val.status = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    result = RegQueryValueExW(key, TargetValue, NULL, (LPDWORD)&val.type, tmp, (LPDWORD)&val.size);
    if (result != ERROR_SUCCESS) {
        free(tmp);
        val.status = result;
        goto cleanup;
    }

    val.buffer = tmp;
    val.status = ERROR_SUCCESS;

cleanup:
    if (key != NULL)
        RegCloseKey(key);
    
    return val;
}

const char *type_name(uint16_t type) {
    switch (type) {
        case 0:  return "UNKNOWN_0";
        case 1:  return "REG_SZ";
        case 2:  return "REG_EXPAND_SZ";
        case 3:  return "REG_BINARY";
        case 4:  return "REG_DWORD";
        case 7:  return "REG_MULTI_SZ";
        case 11: return "REG_QWORD";
        default: {
            static char buf[32];
            sprintf_s(buf, sizeof(buf), "UNKNOWN_%u", type);
            return buf;
        }
    }
}

void print_value(const uint8_t *data, size_t data_len, uint16_t type) {
    switch (type) {
        case 1:
            if (looks_like_utf16_name(data, data_len)) {
                char *s = utf16le_to_utf8(data, data_len, NULL);
                log("  value  = \"%s\" (REG_SZ)", s ? s : "?");
                free(s);
            }
            else {
                log("  value  = <binary %zu bytes, REG_SZ>", data_len);
                hexdump(data, data_len, space);
            }
            return;

        case 3:
            log("  value  = <binary %zu bytes, REG_BINARY>", data_len);
            hexdump(data, data_len, space);
            return;

        case 4:
            if (data_len == 4) {
                uint32_t d;
                memcpy(&d, data, 4);
                log("  value  = %u (0x%08X) (REG_DWORD)", d, d);
            }
            else {
                log("  value  = <nexpected %zu bytes, REG_DWORD>", data_len);
                hexdump(data, data_len, space);
            }
            return;

        case 7:
            log("  value  = <multi-sz, %zu bytes>:", data_len);
            {
                size_t n = data_len / 2;
                int32_t strnum = 0;
                for (size_t i = 0; i < n;) {
                    uint16_t wc = (uint16_t)(data[2 * i] | (data[2 * i + 1] << 8));
                    if (wc == 0) {
                        i++;
                        continue;
                    }

                    size_t start = i;
                    while (i < n) {
                        wc = (uint16_t)(data[2 * i] | (data[2 * i + 1] << 8));
                        if (wc == 0)
                            break;
                        i++;
                    }

                    char *s = utf16le_to_utf8(data + 2 * start, (i - start) * 2, NULL);
                    log("    [%d \"%s\"]", strnum++, s ? s : "?");
                    free(s);
                    i++;
                }
                if (strnum == 0)
                    log("    <empty>");
            }
            return;

        case 11:
            if (data_len == 8) {
                uint64_t q;
                memcpy(&q, data, 8);
                log("  value = %llu (0x%016llX) (REG_QWORD)", q, q);
            }
            else {
                log("  value  = <unexpected %zu bytes, REG_QWORD>", data_len);
                hexdump(data, data_len, space);
            }
            return;

        default:
            log("  value  = <unknown type=%u, %zu bytes>", type, data_len);
            hexdump(data, data_len, space);
            return;
    }
}

#pragma pack(push, 1)

typedef struct {
    uint32_t cbTotalSize;
    uint32_t cbDataSize;
    uint32_t cbEndMarker;
    uint32_t uiReserved;
    uint32_t uiVersion;
} PREFACE;

typedef struct {
    uint16_t cbSize;
    uint16_t cbName;
    uint16_t dtType;
    uint16_t cbData;
    uint32_t uiFlags;
    uint32_t uiReserved;
} ENTRY;

#pragma pack(pop)

int dump_record(const uint8_t *buf, size_t buf_size, size_t ofs, size_t *next_ofs) {
    if (ofs + sizeof(ENTRY) > buf_size)
        return 0;
    
    const ENTRY *e = (const ENTRY *)(buf + ofs);
    if (e->cbSize < sizeof(ENTRY))             return 0;
    if (e->cbSize % 4 != 0)                    return 0;
    if (ofs + e->cbSize > buf_size)            return 0;
    if (e->cbName == 0)                        return 0;
    if (e->cbName % 2 != 0)                    return 0;
    if (e->cbData > e->cbSize - sizeof(ENTRY)) return 0;

    size_t gap      = (size_t)e->cbSize - sizeof(ENTRY) - e->cbName - e->cbData;
    size_t name_ofs = ofs + sizeof(ENTRY);
    size_t data_ofs = name_ofs + e->cbName;

    if (name_ofs + e->cbName > buf_size)                   return 0;
    if (!looks_like_utf16_name(buf + name_ofs, e->cbName)) return 0;

    log(separator);
    log("[0x%08llX] cbSize=%u  cbName=%u  dtType=%u (%s)  cbData=%u"
        "  uiFlags=0x%08X uiReserved=0x%08X",
        ofs, e->cbSize, e->cbName, e->dtType, type_name(e->dtType),
        e->cbData, e->uiFlags, e->uiReserved
    );
    log("  gap    = %zu bytes", gap);

    char *name = utf16le_to_utf8(buf + name_ofs, e->cbName, NULL);
    log("  name   = \"%s\"", name ? name : "?");
    free(name);

    print_value(buf + data_ofs, e->cbData, e->dtType);

    *next_ofs = ofs + e->cbSize;
    return 1;
}

#endif