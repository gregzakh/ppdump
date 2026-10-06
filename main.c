#include "registry.h"

int main(void) {
    struct reg_value data = reg_read();
    if (data.status != ERROR_SUCCESS ||
        data.type != REG_BINARY || data.buffer == NULL) {
        if (data.buffer) {
            free(data.buffer);
            err("Unexpected error has been occured.");
        }
        
        return 0;
    }

    log("=== ProductPolicy ===");
    log("  key   : HKLM\\%ws", ProductPolicy);
    log("  value : %ws", TargetValue);
    log("  size  : %u bytes (0x%08X)\n", data.size, data.size);

    if (data.size < sizeof(PREFACE)) {
        free(data.buffer);
        err("data too small for header");
        return 0;
    }

    const PREFACE *p = (const PREFACE *)data.buffer;
    log("=== Global Header (0x00..0x13, 20 bytes) ===");
    log("  cbTotalSize = 0x%08X (%u)", p->cbTotalSize, p->cbTotalSize);
    log("  cbDataSize  = 0x%08X (%u)", p->cbDataSize, p->cbDataSize);
    log("  cbEndMarker = 0x%08X (%u)", p->cbEndMarker, p->cbEndMarker);
    log("  uiReserved  = 0x%08X", p->uiReserved);
    log("  uiVersion   = %u\n", p->uiVersion);

    uint64_t expected = (uint64_t)sizeof(PREFACE) + p->cbDataSize + p->cbEndMarker;
    log("  integrity   : %zu + %u + %u = %llu vs cbTotalSize=%u => %s\n",
        sizeof(PREFACE), p->cbDataSize, p->cbEndMarker, expected, p->cbTotalSize,
        (expected == p->cbTotalSize) ? "OK" : "MISMATCH"
    );

    log("=== Records (start at 0x14) ===");

    size_t ofs = sizeof(PREFACE);
    size_t recEnd = ofs + p->cbDataSize;
    if (recEnd > data.size)
        recEnd = data.size;
    
    int32_t idx = 0;
    int32_t errors = 0;

    while (ofs + sizeof(ENTRY) <= recEnd) {
        size_t next = 0;
        if (dump_record(data.buffer, data.size, ofs, &next) == 1) {
            ofs = next;
            idx++;
        }
        else {
            log("[9x%08llX] *** PARSE ERROR ***", ofs);
            hexdump(data.buffer + ofs, 64, "  ");
            errors++;
            break;
        }
    }

    log(separator);
    log("Total records  : %d", idx);
    log("Errors occured : %d\n", errors);

    if (ofs + p->cbEndMarker <= data.size) {
        log("=== End Marker @ 0x%08zX", ofs);
        if (p->cbEndMarker >= 4)
            log("  value  : 0x%02X (%02X %02X %02X %02X)",
                data.buffer[ofs], data.buffer[ofs], data.buffer[ofs + 1],
                data.buffer[ofs + 2], data.buffer[ofs + 3]
            );
        else
            log("  value  : 0x%02X", data.buffer[ofs]);
    }

    free(data.buffer);
    return errors ? 0 : 1;
}