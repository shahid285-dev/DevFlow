#include <jni.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp> // optional if you want to parse JSON (add to build)

using json = nlohmann::json;

extern "C" {

// Initialize resolver
JNIEXPORT void JNICALL
Java_com_mobilecodeeditor_cdn_NativeCDNResolver_init_1resolver(JNIEnv* env, jobject thiz) {
    // Initialization code if needed
}

// Simple helper: resolve URL pattern
JNIEXPORT jstring JNICALL
Java_com_mobilecodeeditor_cdn_NativeCDNResolver_resolve_1url(
        JNIEnv* env, jobject thiz,
        jstring j_pattern, jstring j_package, jstring j_version, jstring j_file) {

    const char* pattern = env->GetStringUTFChars(j_pattern, nullptr);
    const char* pkg = env->GetStringUTFChars(j_package, nullptr);
    const char* version = env->GetStringUTFChars(j_version, nullptr);
    const char* file = env->GetStringUTFChars(j_file, nullptr);

    std::string url(pattern);
    std::string search = "{package}";
    size_t pos = url.find(search);
    if (pos != std::string::npos) url.replace(pos, search.length(), pkg);

    search = "{version}";
    pos = url.find(search);
    if (pos != std::string::npos) url.replace(pos, search.length(), version);

    search = "{file}";
    pos = url.find(search);
    if (pos != std::string::npos) url.replace(pos, search.length(), file);

    env->ReleaseStringUTFChars(j_pattern, pattern);
    env->ReleaseStringUTFChars(j_package, pkg);
    env->ReleaseStringUTFChars(j_version, version);
    env->ReleaseStringUTFChars(j_file, file);

    return env->NewStringUTF(url.c_str());
}

}