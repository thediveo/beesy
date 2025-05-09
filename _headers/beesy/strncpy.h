#ifndef __BEESY_STRNCPY_H
#define __BEESY_STRNCPY_H

/*
 * bee_strncpy copies len byte-wide chars from *src to *dst, filling in zero
 * chars when the end of src has been reached before len. This helper does not
 * ensure a trailing zero byte, it is up to the caller to ensure such a zero
 * byte terminator where necessary.
 */
void bee_strncpy(char *dst, const char *src, int len) {
    while (len) {
        if ((*dst = *src) != 0) {
            src++;
        }
        dst++;
        len--;
    }
}

#endif
