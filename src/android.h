#ifndef _JNI_H
#define _JNI_H

#include <jni.h>

jint new_protected_socket();
void free_protected_socket(jint fd);

#endif // _JNI_H
