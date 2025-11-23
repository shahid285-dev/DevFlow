#pragma once

#include <variant>
#include <memory>
#include "AuthDataStructures.h"

namespace Auth {

template<typename T>
class [[nodiscard]] AuthResult {
public:
    explicit AuthResult(T&& value) 
        : result_(std::move(value)) {}
    
    explicit AuthResult(AuthError error) 
        : result_(std::move(error)) {}
    
    [[nodiscard]] bool isSuccess() const noexcept {
        return std::holds_alternative<T>(result_);
    }
    
    [[nodiscard]] bool isError() const noexcept {
        return std::holds_alternative<AuthError>(result_);
    }
    
    [[nodiscard]] T& value() & {
        return std::get<T>(result_);
    }
    
    [[nodiscard]] T&& value() && {
        return std::get<T>(std::move(result_));
    }
    
    [[nodiscard]] const T& value() const& {
        return std::get<T>(result_);
    }
    
    [[nodiscard]] const AuthError& error() const& {
        return std::get<AuthError>(result_);
    }
    
    [[nodiscard]] AuthError&& error() && {
        return std::get<AuthError>(std::move(result_));
    }

private:
    std::variant<T, AuthError> result_;
};


template<>
class [[nodiscard]] AuthResult<void> {
public:
    explicit AuthResult() : success_(true) {}
    explicit AuthResult(AuthError error) : error_(std::move(error)), success_(false) {}
    
    [[nodiscard]] bool isSuccess() const noexcept { return success_; }
    [[nodiscard]] bool isError() const noexcept { return !success_; }
    [[nodiscard]] const AuthError& error() const& { return error_; }

private:
    AuthError error_;
    bool success_;
};

}