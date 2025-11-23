#pragma once

#include <string>
#include <cstring>
#include <algorithm>

namespace Auth {

class secure_string {
public:
    secure_string() = default;
    
    explicit secure_string(const char* str) {
        if (str) {
            data_.assign(str, str + std::strlen(str) + 1);
        }
    }
    
    explicit secure_string(const std::string& str) 
        : data_(str.begin(), str.end()) {
        data_.push_back('\0');
    }
    
    ~secure_string() {
        clear();
    }
    

    secure_string(secure_string&& other) noexcept 
        : data_(std::move(other.data_)) {
    }
    
    secure_string& operator=(secure_string&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
        }
        return *this;
    }
    
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    
    void clear() noexcept {
        if (!data_.empty()) {
            std::fill(data_.begin(), data_.end(), 0);
            data_.clear();
        }
    }
    
    [[nodiscard]] const char* c_str() const noexcept {
        return data_.empty() ? "" : data_.data();
    }
    
    [[nodiscard]] size_t size() const noexcept {
        return data_.empty() ? 0 : data_.size() - 1;
    }
    
    [[nodiscard]] bool empty() const noexcept {
        return data_.empty();
    }

private:
    std::vector<char> data_;
};

} 