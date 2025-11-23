#pragma once

#include "AuthTypes.h"
#include "AuthDataStructures.h"
#include "AuthCallbacks.h"
#include "AuthResult.h"
#include "SecureString.h"
#include <memory>
#include <vector>
#include <atomic>
#include <mutex>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

namespace Auth {

class NetworkManager {
private:
    CURL* curlHandle;
    std::mutex curlMutex;

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
        size_t totalSize = size * nmemb;
        response->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }

public:
    NetworkManager() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curlHandle = curl_easy_init();
    }

    ~NetworkManager() {
        if (curlHandle) {
            curl_easy_cleanup(curlHandle);
        }
        curl_global_cleanup();
    }

    HttpResponse post(const std::string& url, const std::string& data, const std::vector<std::string>& headers = {}) {
        std::lock_guard<std::mutex> lock(curlMutex);
        HttpResponse response;
        
        if (!curlHandle) {
            response.error = "CURL not initialized";
            return response;
        }

        curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_POST, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDSIZE, data.length());
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYHOST, 2L);

        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            headerList = curl_slist_append(headerList, header.c_str());
        }
        if (headerList) {
            curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, headerList);
        }

        CURLcode res = curl_easy_perform(curlHandle);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }

        if (res != CURLE_OK) {
            response.error = curl_easy_strerror(res);
        } else {
            long httpCode = 0;
            curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &httpCode);
            response.statusCode = static_cast<int>(httpCode);
        }

        curl_easy_reset(curlHandle);
        return response;
    }

    HttpResponse get(const std::string& url, const std::vector<std::string>& headers = {}) {
        std::lock_guard<std::mutex> lock(curlMutex);
        HttpResponse response;
        
        if (!curlHandle) {
            response.error = "CURL not initialized";
            return response;
        }

        curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYHOST, 2L);

        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            headerList = curl_slist_append(headerList, header.c_str());
        }
        if (headerList) {
            curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, headerList);
        }

        CURLcode res = curl_easy_perform(curlHandle);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }

        if (res != CURLE_OK) {
            response.error = curl_easy_strerror(res);
        } else {
            long httpCode = 0;
            curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &httpCode);
            response.statusCode = static_cast<int>(httpCode);
        }

        curl_easy_reset(curlHandle);
        return response;
    }

    HttpResponse put(const std::string& url, const std::string& data, const std::vector<std::string>& headers = {}) {
        std::lock_guard<std::mutex> lock(curlMutex);
        HttpResponse response;
        
        if (!curlHandle) {
            response.error = "CURL not initialized";
            return response;
        }

        curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDSIZE, data.length());
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYHOST, 2L);

        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            headerList = curl_slist_append(headerList, header.c_str());
        }
        if (headerList) {
            curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, headerList);
        }

        CURLcode res = curl_easy_perform(curlHandle);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }

        if (res != CURLE_OK) {
            response.error = curl_easy_strerror(res);
        } else {
            long httpCode = 0;
            curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &httpCode);
            response.statusCode = static_cast<int>(httpCode);
        }

        curl_easy_reset(curlHandle);
        return response;
    }

    HttpResponse delete_(const std::string& url, const std::vector<std::string>& headers = {}) {
        std::lock_guard<std::mutex> lock(curlMutex);
        HttpResponse response;
        
        if (!curlHandle) {
            response.error = "CURL not initialized";
            return response;
        }

        curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_CUSTOMREQUEST, "DELETE");
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response.body);
        curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_SSL_VERIFYHOST, 2L);

        struct curl_slist* headerList = nullptr;
        for (const auto& header : headers) {
            headerList = curl_slist_append(headerList, header.c_str());
        }
        if (headerList) {
            curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, headerList);
        }

        CURLcode res = curl_easy_perform(curlHandle);
        
        if (headerList) {
            curl_slist_free_all(headerList);
        }

        if (res != CURLE_OK) {
            response.error = curl_easy_strerror(res);
        } else {
            long httpCode = 0;
            curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &httpCode);
            response.statusCode = static_cast<int>(httpCode);
        }

        curl_easy_reset(curlHandle);
        return response;
    }
};

class BaseAuth {
protected:
    std::vector<AuthStateChangeCallback> stateChangeCallbacks;
    std::vector<AuthErrorCallback> errorCallbacks;
    std::unique_ptr<AuthUser> currentUser;
    std::atomic<AuthState> currentState;
    secure_string apiKey;
    std::string authDomain;
    std::string baseApiUrl;
    std::chrono::seconds tokenRefreshInterval;
    PersistenceType persistenceType;
    std::shared_ptr<NetworkManager> networkManager;
    std::shared_ptr<TokenManager> tokenManager;
    std::string languageCode;
    std::atomic<bool> autoRefreshTokens;
    mutable std::mutex stateMutex;

    struct EndpointConfig {
        std::string signIn;
        std::string signUp;
        std::string signOut;
        std::string refreshToken;
        std::string updateProfile;
        std::string updateEmail;
        std::string updatePassword;
        std::string sendResetEmail;
        std::string confirmReset;
        std::string deleteUser;
        std::string linkProvider;
        std::string unlinkProvider;
        std::string reauthenticate;
    } endpoints;

public:
    BaseAuth(std::string_view key, 
             std::string_view domain,
             std::string_view apiBaseUrl,
             std::shared_ptr<NetworkManager> netManager,
             std::shared_ptr<TokenManager> tokenMgr)
        : authDomain(domain),
          baseApiUrl(apiBaseUrl),
          currentState(AuthState::SignedOut),
          tokenRefreshInterval(std::chrono::hours(1)),
          persistenceType(PersistenceType::LOCAL),
          networkManager(std::move(netManager)),
          tokenManager(std::move(tokenMgr)),
          autoRefreshTokens(true) {
        apiKey = secure_string(key);
        initializeEndpoints();
    }

    virtual ~BaseAuth() = default;

    void configureEndpoint(std::string_view endpointName, std::string_view path) {
        if (endpointName == "signIn") endpoints.signIn = path;
        else if (endpointName == "signUp") endpoints.signUp = path;
        else if (endpointName == "signOut") endpoints.signOut = path;
        else if (endpointName == "refreshToken") endpoints.refreshToken = path;
        else if (endpointName == "updateProfile") endpoints.updateProfile = path;
        else if (endpointName == "updateEmail") endpoints.updateEmail = path;
        else if (endpointName == "updatePassword") endpoints.updatePassword = path;
        else if (endpointName == "sendResetEmail") endpoints.sendResetEmail = path;
        else if (endpointName == "confirmReset") endpoints.confirmReset = path;
        else if (endpointName == "deleteUser") endpoints.deleteUser = path;
        else if (endpointName == "linkProvider") endpoints.linkProvider = path;
        else if (endpointName == "unlinkProvider") endpoints.unlinkProvider = path;
        else if (endpointName == "reauthenticate") endpoints.reauthenticate = path;
    }

    void setAuthState(AuthState newState) noexcept {
        currentState.store(newState, std::memory_order_release);
        notifyStateChange(newState);
    }

    [[nodiscard]] AuthState getAuthState() const noexcept {
        return currentState.load(std::memory_order_acquire);
    }

    [[nodiscard]] virtual AuthResult<std::unique_ptr<AuthUser>> signIn() = 0;
    [[nodiscard]] virtual AuthResult<std::unique_ptr<AuthUser>> signUp() = 0;
    [[nodiscard]] virtual AuthResult<void> signOut() = 0;
    [[nodiscard]] virtual AuthResult<void> linkAccount() = 0;
    [[nodiscard]] virtual AuthResult<void> unlinkAccount() = 0;
    [[nodiscard]] virtual AuthResult<void> reauthenticate() = 0;
    [[nodiscard]] virtual AuthResult<void> updateProfile(const UserProfileChangeRequest& request) = 0;
    [[nodiscard]] virtual AuthResult<std::string> refreshIdToken() = 0;
    [[nodiscard]] virtual AuthResult<void> deleteUser() = 0;

    void addAuthStateListener(AuthStateChangeCallback callback) {
        std::lock_guard lock(stateMutex);
        stateChangeCallbacks.push_back(std::move(callback));
    }

    void addErrorListener(AuthErrorCallback callback) {
        std::lock_guard lock(stateMutex);
        errorCallbacks.push_back(std::move(callback));
    }

    [[nodiscard]] std::unique_ptr<AuthUser> getCurrentUser() const {
        return currentUser ? std::make_unique<AuthUser>(*currentUser) : nullptr;
    }

    [[nodiscard]] bool isSignedIn() const noexcept {
        return currentState.load(std::memory_order_acquire) == AuthState::SignedIn && currentUser != nullptr;
    }

    void setLanguageCode(std::string_view code) {
        languageCode = code;
    }

    void setAutoRefreshTokens(bool enabled) {
        autoRefreshTokens.store(enabled, std::memory_order_release);
    }

protected:
    virtual AuthResult<std::unique_ptr<AuthUser>> makeAuthRequest(
        const std::string& endpoint, 
        const std::string& requestBody) = 0;

    AuthResult<std::unique_ptr<AuthUser>> executeRequest(const std::string& endpoint, const nlohmann::json& requestData) {
        auto headers = getAuthHeaders();
        auto response = networkManager->post(buildUrl(endpoint), requestData.dump(), headers);
        
        if (response.statusCode != 200) {
            return AuthResult<std::unique_ptr<AuthUser>>(parseErrorResponse(response.body));
        }
        
        try {
            auto jsonResponse = nlohmann::json::parse(response.body);
            auto user = parseUserFromResponse(jsonResponse);
            
            if (user) {
                currentUser = std::move(user);
                setAuthState(AuthState::SignedIn);
                
                tokenManager->storeTokens(currentUser->accessToken, 
                                       currentUser->refreshToken,
                                       currentUser->tokenExpiration);
            }
            
            return AuthResult<std::unique_ptr<AuthUser>>(std::make_unique<AuthUser>(*currentUser));
        } catch (const std::exception& e) {
            return AuthResult<std::unique_ptr<AuthUser>>(AuthError{AuthErrorCode::NetworkError,
                                                                 "Failed to parse authentication response",
                                                                 e.what(),
                                                                 "BaseAuth"});
        }
    }

    AuthResult<void> executeVoidRequest(const std::string& endpoint, const nlohmann::json& requestData = {}) {
        auto headers = getAuthHeaders();
        auto response = networkManager->post(buildUrl(endpoint), requestData.dump(), headers);
        
        if (response.statusCode != 200) {
            return AuthResult<void>(parseErrorResponse(response.body));
        }
        
        return AuthResult<void>();
    }

    AuthResult<std::string> executeTokenRequest(const std::string& endpoint, const nlohmann::json& requestData = {}) {
        auto headers = getAuthHeaders();
        auto response = networkManager->post(buildUrl(endpoint), requestData.dump(), headers);
        
        if (response.statusCode != 200) {
            return AuthResult<std::string>(parseErrorResponse(response.body));
        }
        
        try {
            auto jsonResponse = nlohmann::json::parse(response.body);
            std::string token = jsonResponse["id_token"];
            
            if (currentUser) {
                currentUser->accessToken = token;
                int expiresIn = jsonResponse.value("expires_in", 3600);
                currentUser->tokenExpiration = std::chrono::system_clock::now() + std::chrono::seconds(expiresIn);
                
                tokenManager->storeTokens(token, currentUser->refreshToken, currentUser->tokenExpiration);
            }
            
            return AuthResult<std::string>(token);
        } catch (const std::exception& e) {
            return AuthResult<std::string>(AuthError{AuthErrorCode::NetworkError,
                                                   "Failed to parse token response",
                                                   e.what(),
                                                   "BaseAuth"});
        }
    }

    std::string buildUrl(const std::string& endpoint) const {
        return baseApiUrl + endpoint;
    }

    std::vector<std::string> getAuthHeaders() const {
        std::vector<std::string> headers;
        headers.push_back("Content-Type: application/json");
        headers.push_back("X-API-Key: " + std::string(apiKey.c_str()));
        
        if (currentUser && !currentUser->accessToken.empty()) {
            headers.push_back("Authorization: Bearer " + currentUser->accessToken);
        }
        
        if (!languageCode.empty()) {
            headers.push_back("Accept-Language: " + languageCode);
        }
        
        return headers;
    }

    std::unique_ptr<AuthUser> parseUserFromResponse(const nlohmann::json& json) {
        auto user = std::make_unique<AuthUser>();
        
        user->uid = json.value("localId", "");
        user->email = json.value("email", "");
        user->displayName = json.value("displayName", "");
        user->photoURL = json.value("photoUrl", "");
        user->phoneNumber = json.value("phoneNumber", "");
        user->emailVerified = json.value("emailVerified", false);
        user->isAnonymous = json.value("isAnonymous", false);
        user->accessToken = json.value("idToken", "");
        user->refreshToken = json.value("refreshToken", "");
        
        int expiresIn = json.value("expiresIn", 3600);
        user->tokenExpiration = std::chrono::system_clock::now() + std::chrono::seconds(expiresIn);
        
        user->createdAt = std::chrono::system_clock::now();
        user->lastLoginAt = user->createdAt;
        
        return user;
    }
    
    AuthError parseErrorResponse(const std::string& responseBody) {
        try {
            auto json = nlohmann::json::parse(responseBody);
            std::string errorMessage = json.value("error", "Unknown error");
            std::string detailedMessage = json.value("message", "");
            
            AuthErrorCode code = AuthErrorCode::InvalidCredential;
            if (errorMessage.find("INVALID_EMAIL") != std::string::npos) {
                code = AuthErrorCode::InvalidCredential;
            } else if (errorMessage.find("USER_NOT_FOUND") != std::string::npos) {
                code = AuthErrorCode::UserNotFound;
            } else if (errorMessage.find("INVALID_PASSWORD") != std::string::npos) {
                code = AuthErrorCode::InvalidCredential;
            } else if (errorMessage.find("TOKEN_EXPIRED") != std::string::npos) {
                code = AuthErrorCode::TokenExpired;
            } else if (errorMessage.find("NETWORK_ERROR") != std::string::npos) {
                code = AuthErrorCode::NetworkError;
            }
            
            return AuthError{code, errorMessage, detailedMessage, "BaseAuth"};
        } catch (const std::exception&) {
            return AuthError{AuthErrorCode::NetworkError, 
                           "Failed to parse error response", 
                           responseBody, 
                           "BaseAuth"};
        }
    }

    void validateToken(std::string_view token) {
        if (token.empty()) {
            throw std::invalid_argument("Token cannot be empty");
        }
    }

    void refreshTokenInternal(std::string_view refreshToken) {
        auto result = refreshIdToken();
        if (result.isError()) {
            throw std::runtime_error("Failed to refresh token: " + result.error().message);
        }
    }

    void scheduleTokenRefresh(const std::chrono::system_clock::time_point& expiration) {
    }

    void notifyStateChange(AuthState state) {
        std::vector<AuthStateChangeCallback> callbacks;
        {
            std::lock_guard lock(stateMutex);
            callbacks = stateChangeCallbacks;
        }
        
        for (const auto& callback : callbacks) {
            if (callback) {
                callback(state, currentUser);
            }
        }
    }
    
    void notifyError(const AuthError& error) {
        std::vector<AuthErrorCallback> callbacks;
        {
            std::lock_guard lock(stateMutex);
            callbacks = errorCallbacks;
        }
        
        for (const auto& callback : callbacks) {
            if (callback) {
                callback(error);
            }
        }
    }

private:
    void initializeEndpoints() {
        endpoints.signIn = "signIn";
        endpoints.signUp = "signUp";
        endpoints.signOut = "signOut";
        endpoints.refreshToken = "refreshToken";
        endpoints.updateProfile = "updateProfile";
        endpoints.updateEmail = "updateEmail";
        endpoints.updatePassword = "updatePassword";
        endpoints.sendResetEmail = "sendResetEmail";
        endpoints.confirmReset = "confirmReset";
        endpoints.deleteUser = "deleteUser";
        endpoints.linkProvider = "linkProvider";
        endpoints.unlinkProvider = "unlinkProvider";
        endpoints.reauthenticate = "reauthenticate";
    }
};

}