#pragma once

#include <functional>
#include <memory>
#include "AuthTypes.h"

namespace Auth {

class AuthUser;
struct AuthError;

using AuthStateChangeCallback = std::function<void(AuthState state, const std::unique_ptr<AuthUser>& user)>;
using AuthErrorCallback = std::function<void(const AuthError& error)>;
using AuthOperationCallback = std::function<void(const std::unique_ptr<AuthUser>& user)>;
using AuthVoidCallback = std::function<void()>;
using AuthTokenCallback = std::function<void(const std::string& token)>;

}