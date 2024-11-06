#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "debug.h"

bool debug_enabled = false;
void debug(const char *fmt, ...) {
    va_list args;

    if (!debug_enabled) {
        return;
    }

    char* longer_fmt = (char*)malloc(strlen(fmt)+18);
    strcpy(longer_fmt, "AZURE_KEYVAULT: ");
    strcpy(longer_fmt+16, fmt);
    longer_fmt[strlen(fmt)+16] = '\n';
    longer_fmt[strlen(fmt)+17] = '\0';

    va_start(args, fmt);
    vfprintf(stderr, longer_fmt, args);
    va_end(args);

    free(longer_fmt);
}
