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

typedef unsigned short char16_t;

class String8 {
public:
    String8() {
        mString = 0;
    }

    ~String8() {
        if (mString) {
            free(mString);
        }
    }

    void set(const char16_t* o, size_t numChars) {
        if (mString) {
            free(mString);
        }
        mString = (char*) malloc(numChars + 1);
        if (!mString) {
            return;
        }
        for (size_t i = 0; i < numChars; i++) {
            mString[i] = (char) o[i];
        }
        mString[numChars] = '\0';
    }

    const char* string() {
        return mString;
    }
private:
    char* mString;
};

static UnionJNIEnvToVoid uenv;
static jmethodID newProtectedSocketMethod = NULL;
static jmethodID freeProtectedSocketMethod = NULL;

int main (int argc, char **argv);

jint Java_com_github_shadowsocks_daemon_exec(JNIEnv *env, jobject thiz, jobjectArray argv) {

    int argc = argv ? env->GetArrayLength(argv) : 0;
    char **daemon_argv = NULL;
    String8 tmp_8;

    if (argc > 0) {
        daemon_argv = (char **)malloc((argc+1)*sizeof(char *));
        for (int i = 0; i < argc; ++i) {
            jstring arg = reinterpret_cast<jstring>(env->GetObjectArrayElement(argv, i));
            const jchar *str = env->GetStringCritical(arg, 0);
            tmp_8.set(str, env->GetStringLength(arg));
            env->ReleaseStringCritical(arg, str);
            daemon_argv[i] = strdup(tmp_8.string());
        }
        daemon_argv[argc] = NULL;
    }

    int ret = main(argc, daemon_argv);

    for (int i = 0; i < argc; i++) free(daemon_argv[i]);
    free(daemon_argv);

    return ret;
}

/*
 * Register several native methods for one class.
 */
static int registerNativeMethods(JNIEnv* env)
{
    jclass clazz = NULL;

    const char *daemonClassPathName = "com/github/shadowsocks/Daemon";
    const char *vpnClassPathName = "com/github/shadowsocks/ShadowsocksVPNService";

    clazz = env->FindClass(vpnClassPathName);

    if (clazz == NULL)
    {
        LOGE("Native registration unable to find class '%s'", vpnClassPathName);
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

    clazz = env->FindClass(daemonClassPathName);

    JNINativeMethod methods[] = {
        { "exec", "([Ljava/lang/String;)I",
        (void*) Java_com_github_shadowsocks_daemon_exec }
    };

    if (env->RegisterNatives(clazz, methods, 1) < 0) {
        LOGE("RegisterNatives failed for '%s'", daemonClassPathName);
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

    if (registerNativeMethods(env) != JNI_TRUE) {
        LOGE("ERROR: registerNatives failed");
        goto bail;
    }

    result = JNI_VERSION_1_4;

bail:
    return result;
}
