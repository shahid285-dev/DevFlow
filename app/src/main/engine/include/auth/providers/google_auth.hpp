#pragma once

#include "BaseAuth.h"
#include "DatabaseEngine.h"
#include "MetricsEngine.h"
#include <regex>

namespace Auth {

class GoogleAuth : public BaseAuth {
private:
    std::string clientId;
    std::string clientSecret;
    std::string redirectUri;
    
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
        userTable.columns.emplace_back("google_user_id", "TEXT");
        userTable.columns.emplace_back("google_photo_url", "TEXT");
        
        databaseEngine->createTable(userTable);
    }

    bool storeUserLocally(const AuthUser& user, const std::string& googleUserId = "", const std::string& googlePhotoUrl = "") {
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
        
        if (!googleUserId.empty()) {
            userData["google_user_id"] = googleUserId;
        }
        
        if (!googlePhotoUrl.empty()) {
            userData["google_photo_url"] = googlePhotoUrl;
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
        data["provider"] = "google";
        if (!email.empty()) data["email"] = email;
        if (!error.empty()) data["error"] = error;
        
        if (success) {
            metricsEngine->logInfo("GOOGLE_AUTH", operation, "Google authentication operation completed", data);
        } else {
            metricsEngine->logError("GOOGLE_AUTH", operation, "Google authentication operation failed", 0, data);
        }
    }

public:
    GoogleAuth(std::string_view key, 
               std::string_view domain,
               std::string_view apiBaseUrl,
               std::string_view googleClientId,
               std::string_view googleClientSecret,
               std::shared_ptr<NetworkManager> netManager,
               std::shared_ptr<TokenManager> tokenMgr,
               std::shared_ptr<DatabaseEngine> dbEngine = nullptr,
               std::shared_ptr<metrics::MetricsEngine> metricsEng = nullptr)
        : BaseAuth(key, domain, apiBaseUrl, std::move(netManager), std::move(tokenMgr))
        , clientId(googleClientId)
        , clientSecret(googleClientSecret)
        , databaseEngine(std::move(dbEngine))
        , metricsEngine(std::move(metricsEng))
        , userTableName("auth_users")
        , redirectUri("https://" + std::string(domain) + "/callbacks/google") {
        
        configureEndpoint("signIn", "signInWithGoogle");
        configureEndpoint("signUp", "signUpWithGoogle");
        configureEndpoint("linkProvider", "linkGoogleProvider");
        configureEndpoint("unlinkProvider", "unlinkGoogleProvider");
        configureEndpoint("refreshToken", "refreshGoogleToken");
        
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
                     "Use signInWithGoogle instead",
                     "Google provider requires authorization code or ID token",
                     "GoogleAuth"});
    }

    AuthResult<std::unique_ptr<AuthUser>> signInWithGoogle(std::string_view authorizationCode, 
                                                          std::string_view idToken = "",
                                                          std::string_view scope = "email profile") {
        if (authorizationCode.empty() && idToken.empty()) {
            logAuthOperation("signin_google", false, "", "No authorization code or ID token provided");
            return AuthResult<std::unique_ptr<AuthUser>>(
                AuthError{AuthErrorCode::InvalidCredential,
                         "Authorization code or ID token required",
                         "Please provide a valid Google authorization code or ID token",
                         "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        
        if (!authorizationCode.empty()) {
            requestBody["authorization_code"] = std::string(authorizationCode);
        }
        
        if (!idToken.empty()) {
            requestBody["id_token"] = std::string(idToken);
        }
        
        requestBody["client_id"] = clientId;
        requestBody["client_secret"] = clientSecret;
        requestBody["redirect_uri"] = redirectUri;
        requestBody["scope"] = std::string(scope);
        requestBody["returnSecureToken"] = true;
        
        auto result = executeRequest("signIn", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                storeUserLocally(*currentUser, extractGoogleUserId(), extractGooglePhotoUrl());
            }
            logAuthOperation("signin_google", true, currentUser->email);
        } else {
            logAuthOperation("signin_google", false, "", result.error().message);
        }
        
        return result;
    }
    
    AuthResult<std::unique_ptr<AuthUser>> signUp() override {
        return signInWithGoogle("", "");
    }

    AuthResult<std::unique_ptr<AuthUser>> signUpWithGoogle(std::string_view authorizationCode, 
                                                          std::string_view idToken = "",
                                                          std::string_view scope = "email profile") {
        return signInWithGoogle(authorizationCode, idToken, scope);
    }
    
    AuthResult<void> signOut() override {
        if (!currentUser) {
            logAuthOperation("signout", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to sign out",
                                            "GoogleAuth"});
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
            logAuthOperation("link_google", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to link Google account",
                                            "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "google.com";
        
        auto result = executeVoidRequest("linkProvider", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("link_google", true, currentUser->email);
        } else {
            logAuthOperation("link_google", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> unlinkAccount() override {
        if (!currentUser) {
            logAuthOperation("unlink_google", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to unlink Google account",
                                            "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "google.com";
        
        auto result = executeVoidRequest("unlinkProvider", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("unlink_google", true, currentUser->email);
        } else {
            logAuthOperation("unlink_google", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> reauthenticate() override {
        return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                        "Reauthentication not supported for Google OAuth",
                                        "Google OAuth handles reauthentication through new authorization flow",
                                        "GoogleAuth"});
    }

    AuthResult<void> updateProfile(const UserProfileChangeRequest& request) override {
        if (!currentUser) {
            logAuthOperation("update_profile", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to update profile",
                                            "GoogleAuth"});
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
                                                   "GoogleAuth"});
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
                                            "GoogleAuth"});
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

    AuthResult<void> revokeGoogleAccess() {
        if (!currentUser) {
            logAuthOperation("revoke_google_access", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to revoke Google access",
                                            "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "google.com";
        
        auto result = executeVoidRequest("revokeGoogleAccess", requestBody);
        
        if (result.isSuccess()) {
            tokenManager->clearTokens();
            clearLocalUserData();
            currentUser.reset();
            setAuthState(AuthState::SignedOut);
            logAuthOperation("revoke_google_access", true, currentUser ? currentUser->email : "");
        } else {
            logAuthOperation("revoke_google_access", false, currentUser ? currentUser->email : "", result.error().message);
        }
        
        return result;
    }

    AuthResult<void> refreshGoogleTokens() {
        if (!currentUser) {
            logAuthOperation("refresh_google_tokens", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to refresh Google tokens",
                                            "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "google.com";
        
        auto result = executeVoidRequest("refreshGoogleTokens", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("refresh_google_tokens", true, currentUser->email);
        } else {
            logAuthOperation("refresh_google_tokens", false, currentUser->email, result.error().message);
        }
        
        return result;
    }

    AuthResult<std::string> getGoogleAccessToken() {
        if (!currentUser) {
            logAuthOperation("get_google_token", false, "", "No user signed in");
            return AuthResult<std::string>(AuthError{AuthErrorCode::UserNotFound,
                                                   "No authenticated user",
                                                   "Must be signed in to get Google access token",
                                                   "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "google.com";
        
        auto headers = getAuthHeaders();
        auto response = networkManager->post(buildUrl("getGoogleToken"), requestBody.dump(), headers);
        
        if (response.statusCode != 200) {
            logAuthOperation("get_google_token", false, currentUser->email, "Failed to get Google token");
            return AuthResult<std::string>(parseErrorResponse(response.body));
        }
        
        try {
            auto jsonResponse = nlohmann::json::parse(response.body);
            std::string googleToken = jsonResponse["google_access_token"];
            logAuthOperation("get_google_token", true, currentUser->email);
            return AuthResult<std::string>(googleToken);
        } catch (const std::exception& e) {
            logAuthOperation("get_google_token", false, currentUser->email, e.what());
            return AuthResult<std::string>(AuthError{AuthErrorCode::NetworkError,
                                                   "Failed to parse Google token response",
                                                   e.what(),
                                                   "GoogleAuth"});
        }
    }

    AuthResult<void> syncGoogleProfile() {
        if (!currentUser) {
            logAuthOperation("sync_google_profile", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to sync Google profile",
                                            "GoogleAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "google.com";
        
        auto result = executeVoidRequest("syncGoogleProfile", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                updateLocalUserData(*currentUser);
            }
            logAuthOperation("sync_google_profile", true, currentUser->email);
        } else {
            logAuthOperation("sync_google_profile", false, currentUser->email, result.error().message);
        }
        
        return result;
    }

private:
    std::string extractGoogleUserId() {
        if (!currentUser) return "";
        
        if (currentUser->customClaims.count("google_user_id") > 0) {
            return currentUser->customClaims.at("google_user_id");
        }
        return "";
    }

    std::string extractGooglePhotoUrl() {
        if (!currentUser) return "";
        
        if (currentUser->customClaims.count("google_photo_url") > 0) {
            return currentUser->customClaims.at("google_photo_url");
        }
        
        if (!currentUser->photoURL.empty()) {
            return currentUser->photoURL;
        }
        
        return "";
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