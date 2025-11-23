#pragma once

#include "AuthTypes.h"
#include <string>
#include <chrono>
#include <optional>
#include <map>
#include <memory>

namespace Auth {

class AuthUser {
public:
    std::string uid;
    std::string email;
    std::string displayName;
    std::string photoURL;
    std::string phoneNumber;
    bool emailVerified{false};
    bool isAnonymous{false};
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastLoginAt;
    std::map<std::string, std::string> customClaims;
    std::string refreshToken;
    std::string accessToken;
    std::chrono::system_clock::time_point tokenExpiration;

    AuthUser() = default;
    AuthUser(AuthUser&&) noexcept = default;
    AuthUser& operator=(AuthUser&&) noexcept = default;
    
    AuthUser(const AuthUser&) = delete;
    AuthUser& operator=(const AuthUser&) = delete;
};

struct AuthError {
    AuthErrorCode code;
    std::string message;
    std::string details;
    std::string domain;
};

class UserProfileChangeRequest {
public:
    std::optional<std::string> displayName;
    std::optional<std::string> photoURL;
};

class ActionCodeSettings {
public:
    std::string url;
    bool handleCodeInApp{false};
};

} 