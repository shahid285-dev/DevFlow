#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <string_view>

namespace Auth {

class AuthProvider {
protected:
    std::string providerId;
    std::vector<std::string> scopes;
    std::unordered_map<std::string, std::string> customParameters;

public:
    explicit AuthProvider(std::string_view id) : providerId(id) {}
    virtual ~AuthProvider() = default;
    
    [[nodiscard]] const std::string& getProviderId() const noexcept { return providerId; }
    
    void addScope(std::string_view scope) {
        scopes.emplace_back(scope);
    }
    
    void setCustomParameter(std::string_view key, std::string_view value) {
        customParameters[std::string(key)] = std::string(value);
    }
};

}