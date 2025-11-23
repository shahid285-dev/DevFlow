#pragma once

#include "BaseAuth.h"
#include "DatabaseEngine.h"
#include "MetricsEngine.h"
#include <regex>

namespace Auth {

class MicrosoftAuth : public BaseAuth {
private:
    std::string clientId;
    std::string clientSecret;
    std::string redirectUri;
    std::string tenantId;
    
    std::shared_ptr<DatabaseEngine> databaseEngine;
    std::shared_ptr<metrics::MetricsEngine> metricsEngine;
    std::string userTableName;

    void initializeLocalStorage() {
        if (!databaseEngine) return;
        
        DatabaseTable userTable;
        userTable.name = userTableName;
        
        userTable.columns.emplace_back("uid", "TEXT");
        userTable.columns.back().primaryKey = true;
        userTable.columns.back().notNull = true;
        
        userTable.columns.emplace_back("email", "TEXT");
        userTable.columns.back().notNull = true;
        userTable.columns.back().indexed = true;
        
        userTable.columns.emplace_back("display_name", "TEXT");
        userTable.columns.emplace_back("photo_url", "TEXT");
        userTable.columns.emplace_back("phone_number", "TEXT");
        userTable.columns.emplace_back("email_verified", "INTEGER");
        userTable.columns.emplace_back("is_anonymous", "INTEGER");
        userTable.columns.emplace_back("access_token", "TEXT");
        userTable.columns.emplace_back("refresh_token", "TEXT");
        userTable.columns.emplace_back("token_expiration", "INTEGER");
        userTable.columns.emplace_back("created_at", "INTEGER");
        userTable.columns.emplace_back("last_login_at", "INTEGER");
        userTable.columns.emplace_back("custom_claims", "TEXT");
        userTable.columns.emplace_back("microsoft_user_id", "TEXT");
        userTable.columns.emplace_back("microsoft_tenant_id", "TEXT");
        
        databaseEngine->createTable(userTable);
    }

    bool storeUserLocally(const AuthUser& user, const std::string& microsoftUserId = "", const std::string& microsoftTenantId = "") {
        if (!databaseEngine) return false;
        
        std::unordered_map<std::string, std::string> userData;
        userData["uid"] = user.uid;
        userData["email"] = user.email;
        userData["display_name"] = user.displayName;
        userData["photo_url"] = user.photoURL;
        userData["phone_number"] = user.phoneNumber;
        userData["email_verified"] = user.emailVerified ? "1" : "0";
        userData["is_anonymous"] = user.isAnonymous ? "1" : "0";
        userData["access_token"] = user.accessToken;
        userData["refresh_token"] = user.refreshToken;
        userData["token_expiration"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.tokenExpiration.time_since_epoch()).count());
        userData["created_at"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.createdAt.time_since_epoch()).count());
        userData["last_login_at"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.lastLoginAt.time_since_epoch()).count());
        
        if (!microsoftUserId.empty()) {
            userData["microsoft_user_id"] = microsoftUserId;
        }
        
        if (!microsoftTenantId.empty()) {
            userData["microsoft_tenant_id"] = microsoftTenantId;
        }
        
        if (!user.customClaims.empty()) {
            userData["custom_claims"] = nlohmann::json(user.customClaims).dump();
        }
        
        auto result = databaseEngine->insert(userTableName, userData, "REPLACE");
        return result.success;
    }

    std::unique_ptr<AuthUser> loadUserFromLocalStorage() {
        if (!databaseEngine) return nullptr;
        
        auto result = databaseEngine->select(userTableName, {"*"}, "", "last_login_at DESC", 1);
        if (!result.success || result.data.empty()) {
            return nullptr;
        }
        
        const auto& row = result.data[0];
        auto user = std::make_unique<AuthUser>();
        
        user->uid = row.at("uid");
        user->email = row.at("email");
        user->displayName = row.at("display_name");
        user->photoURL = row.at("photo_url");
        user->phoneNumber = row.at("phone_number");
        user->emailVerified = row.at("email_verified") == "1";
        user->isAnonymous = row.at("is_anonymous") == "1";
        user->accessToken = row.at("access_token");
        user->refreshToken = row.at("refresh_token");
        
        int64_t tokenExpiration = std::stoll(row.at("token_expiration"));
        user->tokenExpiration = std::chrono::system_clock::time_point(std::chrono::seconds(tokenExpiration));
        
        int64_t createdAt = std::stoll(row.at("created_at"));
        user->createdAt = std::chrono::system_clock::time_point(std::chrono::seconds(createdAt));
        
        int64_t lastLoginAt = std::stoll(row.at("last_login_at"));
        user->lastLoginAt = std::chrono::system_clock::time_point(std::chrono::seconds(lastLoginAt));
        
        if (row.find("custom_claims") != row.end() && !row.at("custom_claims").empty()) {
            try {
                auto claimsJson = nlohmann::json::parse(row.at("custom_claims"));
                for (auto& [key, value] : claimsJson.items()) {
                    user->customClaims[key] = value.get<std::string>();
                }
            } catch (const std::exception&) {
            }
        }
        
        return user;
    }

    void clearLocalUserData() {
        if (!databaseEngine) return;
        databaseEngine->deleteRows(userTableName);
    }

    void updateLocalUserData(const AuthUser& user) {
        if (!databaseEngine) return;
        
        std::unordered_map<std::string, std::string> updates;
        updates["display_name"] = user.displayName;
        updates["photo_url"] = user.photoURL;
        updates["phone_number"] = user.phoneNumber;
        updates["email_verified"] = user.emailVerified ? "1" : "0";
        updates["access_token"] = user.accessToken;
        updates["refresh_token"] = user.refreshToken;
        updates["token_expiration"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.tokenExpiration.time_since_epoch()).count());
        updates["last_login_at"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.lastLoginAt.time_since_epoch()).count());
        
        if (!user.customClaims.empty()) {
            updates["custom_claims"] = nlohmann::json(user.customClaims).dump();
        }
        
        databaseEngine->update(userTableName, updates, "uid = '" + user.uid + "'");
    }

    void logAuthOperation(const std::string& operation, bool success, const std::string& email = "", const std::string& error = "") {
        if (!metricsEngine) return;
        
        nlohmann::json data;
        data["operation"] = operation;
        data["success"] = success;
        data["provider"] = "microsoft";
        if (!email.empty()) data["email"] = email;
        if (!error.empty()) data["error"] = error;
        
        if (success) {
            metricsEngine->logInfo("MICROSOFT_AUTH", operation, "Microsoft authentication operation completed", data);
        } else {
            metricsEngine->logError("MICROSOFT_AUTH", operation, "Microsoft authentication operation failed", 0, data);
        }
    }

public:
    MicrosoftAuth(std::string_view key, 
                  std::string_view domain,
                  std::string_view apiBaseUrl,
                  std::string_view microsoftClientId,
                  std::string_view microsoftClientSecret,
                  std::string_view microsoftTenantId,
                  std::shared_ptr<NetworkManager> netManager,
                  std::shared_ptr<TokenManager> tokenMgr,
                  std::shared_ptr<DatabaseEngine> dbEngine = nullptr,
                  std::shared_ptr<metrics::MetricsEngine> metricsEng = nullptr)
        : BaseAuth(key, domain, apiBaseUrl, std::move(netManager), std::move(tokenMgr))
        , clientId(microsoftClientId)
        , clientSecret(microsoftClientSecret)
        , tenantId(microsoftTenantId)
        , databaseEngine(std::move(dbEngine))
        , metricsEngine(std::move(metricsEng))
        , userTableName("auth_users")
        , redirectUri("https://" + std::string(domain) + "/callbacks/microsoft") {
        
        configureEndpoint("signIn", "signInWithMicrosoft");
        configureEndpoint("signUp", "signUpWithMicrosoft");
        configureEndpoint("linkProvider", "linkMicrosoftProvider");
        configureEndpoint("unlinkProvider", "unlinkMicrosoftProvider");
        configureEndpoint("refreshToken", "refreshMicrosoftToken");
        
        if (databaseEngine) {
            initializeLocalStorage();
            auto cachedUser = loadUserFromLocalStorage();
            if (cachedUser && !isTokenExpired(*cachedUser)) {
                currentUser = std::move(cachedUser);
                setAuthState(AuthState::SignedIn);
                logAuthOperation("load_cached_user", true, currentUser->email);
            }
        }
    }

    AuthResult<std::unique_ptr<AuthUser>> signIn() override {
        return AuthResult<std::unique_ptr<AuthUser>>(
            AuthError{AuthErrorCode::InvalidCredential,
                     "Use signInWithMicrosoft instead",
                     "Microsoft provider requires authorization code",
                     "MicrosoftAuth"});
    }

    AuthResult<std::unique_ptr<AuthUser>> signInWithMicrosoft(std::string_view authorizationCode, 
                                                             std::string_view scope = "User.Read") {
        if (authorizationCode.empty()) {
            logAuthOperation("signin_microsoft", false, "", "No authorization code provided");
            return AuthResult<std::unique_ptr<AuthUser>>(
                AuthError{AuthErrorCode::InvalidCredential,
                         "Authorization code required",
                         "Please provide a valid Microsoft authorization code",
                         "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["authorization_code"] = std::string(authorizationCode);
        requestBody["client_id"] = clientId;
        requestBody["client_secret"] = clientSecret;
        requestBody["tenant_id"] = tenantId;
        requestBody["redirect_uri"] = redirectUri;
        requestBody["scope"] = std::string(scope);
        requestBody["returnSecureToken"] = true;
        
        auto result = executeRequest("signIn", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                storeUserLocally(*currentUser, extractMicrosoftUserId(), extractMicrosoftTenantId());
            }
            logAuthOperation("signin_microsoft", true, currentUser->email);
        } else {
            logAuthOperation("signin_microsoft", false, "", result.error().message);
        }
        
        return result;
    }
    
    AuthResult<std::unique_ptr<AuthUser>> signUp() override {
        return signInWithMicrosoft("");
    }

    AuthResult<std::unique_ptr<AuthUser>> signUpWithMicrosoft(std::string_view authorizationCode, 
                                                             std::string_view scope = "User.Read") {
        return signInWithMicrosoft(authorizationCode, scope);
    }
    
    AuthResult<void> signOut() override {
        if (!currentUser) {
            logAuthOperation("signout", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to sign out",
                                            "MicrosoftAuth"});
        }
        
        std::string userEmail = currentUser->email;
        
        auto result = executeVoidRequest("signOut");
        
        if (result.isSuccess()) {
            tokenManager->clearTokens();
            clearLocalUserData();
            currentUser.reset();
            setAuthState(AuthState::SignedOut);
            logAuthOperation("signout", true, userEmail);
        } else {
            logAuthOperation("signout", false, userEmail, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> linkAccount() override {
        if (!currentUser) {
            logAuthOperation("link_microsoft", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to link Microsoft account",
                                            "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "microsoft.com";
        
        auto result = executeVoidRequest("linkProvider", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("link_microsoft", true, currentUser->email);
        } else {
            logAuthOperation("link_microsoft", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> unlinkAccount() override {
        if (!currentUser) {
            logAuthOperation("unlink_microsoft", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to unlink Microsoft account",
                                            "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "microsoft.com";
        
        auto result = executeVoidRequest("unlinkProvider", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("unlink_microsoft", true, currentUser->email);
        } else {
            logAuthOperation("unlink_microsoft", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> reauthenticate() override {
        return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                        "Reauthentication not supported for Microsoft OAuth",
                                        "Microsoft OAuth handles reauthentication through new authorization flow",
                                        "MicrosoftAuth"});
    }

    AuthResult<void> updateProfile(const UserProfileChangeRequest& request) override {
        if (!currentUser) {
            logAuthOperation("update_profile", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to update profile",
                                            "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        
        if (request.displayName.has_value()) {
            requestBody["displayName"] = request.displayName.value();
        }
        if (request.photoURL.has_value()) {
            requestBody["photoURL"] = request.photoURL.value();
        }
        
        auto result = executeVoidRequest("updateProfile", requestBody);
        
        if (result.isSuccess()) {
            if (request.displayName.has_value()) {
                currentUser->displayName = request.displayName.value();
            }
            if (request.photoURL.has_value()) {
                currentUser->photoURL = request.photoURL.value();
            }
            
            if (databaseEngine) {
                updateLocalUserData(*currentUser);
            }
            logAuthOperation("update_profile", true, currentUser->email);
        } else {
            logAuthOperation("update_profile", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<std::string> refreshIdToken() override {
        if (!currentUser || currentUser->refreshToken.empty()) {
            logAuthOperation("refresh_token", false, "", "No refresh token available");
            return AuthResult<std::string>(AuthError{AuthErrorCode::UserNotFound,
                                                   "No authenticated user or refresh token",
                                                   "Must be signed in with valid refresh token",
                                                   "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["grant_type"] = "refresh_token";
        requestBody["refresh_token"] = currentUser->refreshToken;
        
        auto result = executeTokenRequest("refreshToken", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                updateLocalUserData(*currentUser);
            }
            logAuthOperation("refresh_token", true, currentUser->email);
        } else {
            logAuthOperation("refresh_token", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> deleteUser() override {
        if (!currentUser) {
            logAuthOperation("delete_user", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to delete account",
                                            "MicrosoftAuth"});
        }
        
        std::string userEmail = currentUser->email;
        
        auto result = executeVoidRequest("deleteUser");
        
        if (result.isSuccess()) {
            tokenManager->clearTokens();
            clearLocalUserData();
            currentUser.reset();
            setAuthState(AuthState::SignedOut);
            logAuthOperation("delete_user", true, userEmail);
        } else {
            logAuthOperation("delete_user", false, userEmail, result.error().message);
        }
        
        return result;
    }

    AuthResult<void> revokeMicrosoftAccess() {
        if (!currentUser) {
            logAuthOperation("revoke_microsoft_access", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to revoke Microsoft access",
                                            "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "microsoft.com";
        
        auto result = executeVoidRequest("revokeMicrosoftAccess", requestBody);
        
        if (result.isSuccess()) {
            tokenManager->clearTokens();
            clearLocalUserData();
            currentUser.reset();
            setAuthState(AuthState::SignedOut);
            logAuthOperation("revoke_microsoft_access", true, currentUser ? currentUser->email : "");
        } else {
            logAuthOperation("revoke_microsoft_access", false, currentUser ? currentUser->email : "", result.error().message);
        }
        
        return result;
    }

    AuthResult<void> refreshMicrosoftTokens() {
        if (!currentUser) {
            logAuthOperation("refresh_microsoft_tokens", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to refresh Microsoft tokens",
                                            "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "microsoft.com";
        
        auto result = executeVoidRequest("refreshMicrosoftTokens", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("refresh_microsoft_tokens", true, currentUser->email);
        } else {
            logAuthOperation("refresh_microsoft_tokens", false, currentUser->email, result.error().message);
        }
        
        return result;
    }

    AuthResult<std::string> getMicrosoftAccessToken() {
        if (!currentUser) {
            logAuthOperation("get_microsoft_token", false, "", "No user signed in");
            return AuthResult<std::string>(AuthError{AuthErrorCode::UserNotFound,
                                                   "No authenticated user",
                                                   "Must be signed in to get Microsoft access token",
                                                   "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "microsoft.com";
        
        auto headers = getAuthHeaders();
        auto response = networkManager->post(buildUrl("getMicrosoftToken"), requestBody.dump(), headers);
        
        if (response.statusCode != 200) {
            logAuthOperation("get_microsoft_token", false, currentUser->email, "Failed to get Microsoft token");
            return AuthResult<std::string>(parseErrorResponse(response.body));
        }
        
        try {
            auto jsonResponse = nlohmann::json::parse(response.body);
            std::string microsoftToken = jsonResponse["microsoft_access_token"];
            logAuthOperation("get_microsoft_token", true, currentUser->email);
            return AuthResult<std::string>(microsoftToken);
        } catch (const std::exception& e) {
            logAuthOperation("get_microsoft_token", false, currentUser->email, e.what());
            return AuthResult<std::string>(AuthError{AuthErrorCode::NetworkError,
                                                   "Failed to parse Microsoft token response",
                                                   e.what(),
                                                   "MicrosoftAuth"});
        }
    }

    AuthResult<void> syncMicrosoftProfile() {
        if (!currentUser) {
            logAuthOperation("sync_microsoft_profile", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to sync Microsoft profile",
                                            "MicrosoftAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "microsoft.com";
        
        auto result = executeVoidRequest("syncMicrosoftProfile", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                updateLocalUserData(*currentUser);
            }
            logAuthOperation("sync_microsoft_profile", true, currentUser->email);
        } else {
            logAuthOperation("sync_microsoft_profile", false, currentUser->email, result.error().message);
        }
        
        return result;
    }

    AuthResult<void> changeTenant(std::string_view newTenantId) {
        if (newTenantId.empty()) {
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                            "Tenant ID cannot be empty",
                                            "Please provide a valid Microsoft tenant ID",
                                            "MicrosoftAuth"});
        }
        
        tenantId = newTenantId;
        logAuthOperation("change_tenant", true, "", "Tenant ID updated to: " + std::string(newTenantId));
        return AuthResult<void>();
    }

private:
    std::string extractMicrosoftUserId() {
        if (!currentUser) return "";
        
        if (currentUser->customClaims.count("microsoft_user_id") > 0) {
            return currentUser->customClaims.at("microsoft_user_id");
        }
        return "";
    }

    std::string extractMicrosoftTenantId() {
        if (!currentUser) return "";
        
        if (currentUser->customClaims.count("microsoft_tenant_id") > 0) {
            return currentUser->customClaims.at("microsoft_tenant_id");
        }
        return tenantId;
    }

    bool isTokenExpired(const AuthUser& user) const {
        return std::chrono::system_clock::now() >= user.tokenExpiration;
    }

protected:
    AuthResult<std::unique_ptr<AuthUser>> makeAuthRequest(
        const std::string& endpoint, 
        const std::string& requestBody) override {
        return executeRequest(endpoint, nlohmann::json::parse(requestBody));
    }
};

} 