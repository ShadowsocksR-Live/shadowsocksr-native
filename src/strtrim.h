#ifndef __STR_TRIM_H__
#define __STR_TRIM_H__

#include <stddef.h>

enum str_trim_type {
    trim_type_none = 0,
    trim_type_trailing = 1,
    trim_type_leading = 2,
    trim_type_both = trim_type_leading | trim_type_trailing,
};

char* strtrim(char* src, enum str_trim_type trim_type, void* (*allocator)(size_t));

#endif // __STR_TRIM_H__
