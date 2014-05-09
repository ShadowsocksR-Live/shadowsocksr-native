#define LOG_TAG "Shadowsocks"

#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "android.h"

#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); } while(0)
#define LOGW(...) do { __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); } while(0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); } while(0)

/*
 * This is called by the VM when the shared library is first loaded.
 */

typedef union {
    JNIEnv* env;
    void* venv;
} UnionJNIEnvToVoid;

static UnionJNIEnvToVoid uenv;
static jmethodID newProtectedSocketMethod = NULL;
static jmethodID freeProtectedSocketMethod = NULL;
static jclass clazz = NULL;

static const char *classPathName = "com/github/shadowsocks/Socket";

/*
 * Register several native methods for one class.
 */
static int registerNativeMethods(JNIEnv* env, const char* className)
{
    if (clazz == NULL)
    {
        clazz = env->FindClass(className);
    }
    if (clazz == NULL)
    {
        LOGE("Native registration unable to find class '%s'", className);
        return JNI_FALSE;
    }
    newProtectedSocketMethod = env->GetStaticMethodID(clazz, "newProtectedSocket", "()I");
    if (newProtectedSocketMethod < 0)
    {
        LOGE("RegisterNatives failed for newProtectedSocketMethod");
        return JNI_FALSE;
    }
    freeProtectedSocketMethod = env->GetStaticMethodID(clazz, "freeProtectedSocket", "(I)V");
    if (freeProtectedSocketMethod < 0)
    {
        LOGE("RegisterNatives failed for freeProtectedSocketMethod");
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

jint new_protected_socket()
{
    if (newProtectedSocketMethod != NULL)
    {
        JNIEnv* env = uenv.env;
        return env->CallStaticIntMethod(clazz, newProtectedSocketMethod);
    }
    return -1;
}

void free_protected_socket(jint fd)
{
    if (newProtectedSocketMethod != NULL)
    {
        JNIEnv* env = uenv.env;
        env->CallStaticVoidMethod(clazz, freeProtectedSocketMethod, fd);
    }
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    uenv.venv = NULL;
    jint result = -1;
    JNIEnv* env = NULL;

    LOGI("JNI_OnLoad");

    if (vm->GetEnv(&uenv.venv, JNI_VERSION_1_4) != JNI_OK) {
        LOGE("ERROR: GetEnv failed");
        goto bail;
    }
    env = uenv.env;

    if (registerNativeMethods(env, classPathName) != JNI_TRUE) {
        LOGE("ERROR: registerNatives failed");
        goto bail;
    }

    result = JNI_VERSION_1_4;

bail:
    return result;
}
