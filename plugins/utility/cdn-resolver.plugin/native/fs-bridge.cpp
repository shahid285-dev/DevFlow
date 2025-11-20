#include <jni.h>
#include <string>
#include <fstream>
#include <sstream>
#include <android/log.h>

#define LOG_TAG "NativeFS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

// Initialize filesystem bridge
JNIEXPORT void JNICALL
Java_com_mobilecodeeditor_cdn_NativeFS_init_1fs(JNIEnv* env, jobject thiz) {
    LOGI("NativeFS initialized");
}

// Write a text file to internal storage
JNIEXPORT jboolean JNICALL
Java_com_mobilecodeeditor_cdn_NativeFS_writeFile(
        JNIEnv* env, jobject thiz,
        jstring j_path, jstring j_content) {

    const char* path = env->GetStringUTFChars(j_path, nullptr);
    const char* content = env->GetStringUTFChars(j_content, nullptr);

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        LOGE("Failed to open file for writing: %s", path);
        env->ReleaseStringUTFChars(j_path, path);
        env->ReleaseStringUTFChars(j_content, content);
        return JNI_FALSE;
    }

    file << content;
    file.close();

    env->ReleaseStringUTFChars(j_path, path);
    env->ReleaseStringUTFChars(j_content, content);

    LOGI("File written successfully: %s", path);
    return JNI_TRUE;
}

// Read a text file from internal storage
JNIEXPORT jstring JNICALL
Java_com_mobilecodeeditor_cdn_NativeFS_readFile(
        JNIEnv* env, jobject thiz,
        jstring j_path) {

    const char* path = env->GetStringUTFChars(j_path, nullptr);
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open()) {
        LOGE("Failed to open file for reading: %s", path);
        env->ReleaseStringUTFChars(j_path, path);
        return env->NewStringUTF("");
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    file.close();
    env->ReleaseStringUTFChars(j_path, path);

    return env->NewStringUTF(ss.str().c_str());
}

// Append content to a file
JNIEXPORT jboolean JNICALL
Java_com_mobilecodeeditor_cdn_NativeFS_appendFile(
        JNIEnv* env, jobject thiz,
        jstring j_path, jstring j_content) {

    const char* path = env->GetStringUTFChars(j_path, nullptr);
    const char* content = env->GetStringUTFChars(j_content, nullptr);

    std::ofstream file(path, std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        LOGE("Failed to open file for appending: %s", path);
        env->ReleaseStringUTFChars(j_path, path);
        env->ReleaseStringUTFChars(j_content, content);
        return JNI_FALSE;
    }

    file << content;
    file.close();

    env->ReleaseStringUTFChars(j_path, path);
    env->ReleaseStringUTFChars(j_content, content);

    LOGI("Content appended successfully: %s", path);
    return JNI_TRUE;
}

}