//
// Created by ssrlive on 2020-09-09.
//

#ifndef __SSR_NATIVE_EXE_FILE_PATH_H__
#define __SSR_NATIVE_EXE_FILE_PATH_H__

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

char* exe_file_path(void* (*allocator)(size_t));

#endif // __SSR_NATIVE_EXE_FILE_PATH_H__
