#include <string.h>
#include <ctype.h>

#include "strtrim.h"

static char* trim_leading_space(char* str);
static char* trim_trailing_space(char* str);

char* strtrim(char* src, enum str_trim_type trim_type, void* (*allocator)(size_t)) {
    char* result = NULL;
    if (src == NULL) {
        return NULL;
    }
    if (allocator) {
        result = (char*)allocator(strlen(src) + 1);
        if (result == NULL) { return NULL; }
        strcpy(result, src);
    }
    else {
        result = src;
    }

    if ((trim_type & trim_type_leading) == trim_type_leading) {
        result = trim_leading_space(result);
    }
    if ((trim_type & trim_type_trailing) == trim_type_trailing) {
        result = trim_trailing_space(result);
    }

    return result;
}

static char* trim_leading_space(char* str) {
    char* end = str;
    if (str == NULL) { return NULL; }
    while (isspace((unsigned char)*end)) { end++; }
    if (end != str) {
        memmove(str, end, strlen(end) + 1);
    }
    return str;
}

static char* trim_trailing_space(char* str) {
    char* end;
    if (str == NULL || strlen(str) == 0) { return str; }
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) { end--; }

    // Write new null terminator character
    end[1] = '\0';

    return str;
}
