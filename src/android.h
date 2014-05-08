#ifndef _JNI_H
#define _JNI_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

jint new_protected_socket();
void free_protected_socket(jint fd);

#ifdef __cplusplus
}
#endif

#endif // _JNI_H
