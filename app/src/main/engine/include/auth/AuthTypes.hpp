#pragma once

#include <string>
#include <chrono>
#include <optional>
#include <map>
#include <vector>

namespace Auth {
    
enum class AuthState : uint8_t {
    SignedOut,
    SignedIn,
    SigningIn,
    SigningOut,
    RefreshingToken,
    Error
};

enum class PersistenceType : uint8_t {
    LOCAL,
    SESSION,
    NONE
};

enum class AuthErrorCode : int {
    InvalidCredential = 1,
    UserDisabled,
    UserNotFound,
    TokenExpired,
    NetworkError,
    TooManyAttempts,
    InvalidToken,
    ProviderError
};

}