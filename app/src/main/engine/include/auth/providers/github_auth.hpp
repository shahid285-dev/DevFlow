#pragma once

#include "BaseAuth.h"
#include "DatabaseEngine.h"
#include "MetricsEngine.h"
#include <regex>

namespace Auth {

class GitHubAuth : public BaseAuth {
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
        userTable.columns.emplace_back("github_user_id", "TEXT");
        userTable.columns.emplace_back("github_username", "TEXT");
        
        databaseEngine->createTable(userTable);
    }

    bool storeUserLocally(const AuthUser& user, const std::string& githubUserId = "", const std::string& githubUsername = "") {
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
        
        if (!githubUserId.empty()) {
            userData["github_user_id"] = githubUserId;
        }
        
        if (!githubUsername.empty()) {
            userData["github_username"] = githubUsername;
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
        data["provider"] = "github";
        if (!email.empty()) data["email"] = email;
        if (!error.empty()) data["error"] = error;
        
        if (success) {
            metricsEngine->logInfo("GITHUB_AUTH", operation, "GitHub authentication operation completed", data);
        } else {
            metricsEngine->logError("GITHUB_AUTH", operation, "GitHub authentication operation failed", 0, data);
        }
    }

public:
    GitHubAuth(std::string_view key, 
               std::string_view domain,
               std::string_view apiBaseUrl,
               std::string_view githubClientId,
               std::string_view githubClientSecret,
               std::shared_ptr<NetworkManager> netManager,
               std::shared_ptr<TokenManager> tokenMgr,
               std::shared_ptr<DatabaseEngine> dbEngine = nullptr,
               std::shared_ptr<metrics::MetricsEngine> metricsEng = nullptr)
        : BaseAuth(key, domain, apiBaseUrl, std::move(netManager), std::move(tokenMgr))
        , clientId(githubClientId)
        , clientSecret(githubClientSecret)
        , databaseEngine(std::move(dbEngine))
        , metricsEngine(std::move(metricsEng))
        , userTableName("auth_users")
        , redirectUri("https://" + std::string(domain) + "/callbacks/github") {
        
        configureEndpoint("signIn", "signInWithGitHub");
        configureEndpoint("signUp", "signUpWithGitHub");
        configureEndpoint("linkProvider", "linkGitHubProvider");
        configureEndpoint("unlinkProvider", "unlinkGitHubProvider");
        configureEndpoint("refreshToken", "refreshGitHubToken");
        
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
                     "Use signInWithGitHub instead",
                     "GitHub provider requires authorization code",
                     "GitHubAuth"});
    }

    AuthResult<std::unique_ptr<AuthUser>> signInWithGitHub(std::string_view authorizationCode, 
                                                          std::string_view scope = "user:email") {
        if (authorizationCode.empty()) {
            logAuthOperation("signin_github", false, "", "No authorization code provided");
            return AuthResult<std::unique_ptr<AuthUser>>(
                AuthError{AuthErrorCode::InvalidCredential,
                         "Authorization code required",
                         "Please provide a valid GitHub authorization code",
                         "GitHubAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["authorization_code"] = std::string(authorizationCode);
        requestBody["client_id"] = clientId;
        requestBody["client_secret"] = clientSecret;
        requestBody["redirect_uri"] = redirectUri;
        requestBody["scope"] = std::string(scope);
        requestBody["returnSecureToken"] = true;
        
        auto result = executeRequest("signIn", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                storeUserLocally(*currentUser, extractGitHubUserId(), extractGitHubUsername());
            }
            logAuthOperation("signin_github", true, currentUser->email);
        } else {
            logAuthOperation("signin_github", false, "", result.error().message);
        }
        
        return result;
    }
    
    AuthResult<std::unique_ptr<AuthUser>> signUp() override {
        return signInWithGitHub("");
    }

    AuthResult<std::unique_ptr<AuthUser>> signUpWithGitHub(std::string_view authorizationCode, 
                                                          std::string_view scope = "user:email") {
        return signInWithGitHub(authorizationCode, scope);
    }
    
    AuthResult<void> signOut() override {
        if (!currentUser) {
            logAuthOperation("signout", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to sign out",
                                            "GitHubAuth"});
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
            logAuthOperation("link_github", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to link GitHub account",
                                            "GitHubAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "github.com";
        
        auto result = executeVoidRequest("linkProvider", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("link_github", true, currentUser->email);
        } else {
            logAuthOperation("link_github", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> unlinkAccount() override {
        if (!currentUser) {
            logAuthOperation("unlink_github", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to unlink GitHub account",
                                            "GitHubAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "github.com";
        
        auto result = executeVoidRequest("unlinkProvider", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("unlink_github", true, currentUser->email);
        } else {
            logAuthOperation("unlink_github", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> reauthenticate() override {
        return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                        "Reauthentication not supported for GitHub OAuth",
                                        "GitHub OAuth handles reauthentication through new authorization flow",
                                        "GitHubAuth"});
    }

    AuthResult<void> updateProfile(const UserProfileChangeRequest& request) override {
        if (!currentUser) {
            logAuthOperation("update_profile", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to update profile",
                                            "GitHubAuth"});
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
                                                   "GitHubAuth"});
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
                                            "GitHubAuth"});
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

    AuthResult<void> revokeGitHubAccess() {
        if (!currentUser) {
            logAuthOperation("revoke_github_access", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to revoke GitHub access",
                                            "GitHubAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "github.com";
        
        auto result = executeVoidRequest("revokeGitHubAccess", requestBody);
        
        if (result.isSuccess()) {
            tokenManager->clearTokens();
            clearLocalUserData();
            currentUser.reset();
            setAuthState(AuthState::SignedOut);
            logAuthOperation("revoke_github_access", true, currentUser ? currentUser->email : "");
        } else {
            logAuthOperation("revoke_github_access", false, currentUser ? currentUser->email : "", result.error().message);
        }
        
        return result;
    }

    AuthResult<void> refreshGitHubTokens() {
        if (!currentUser) {
            logAuthOperation("refresh_github_tokens", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to refresh GitHub tokens",
                                            "GitHubAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "github.com";
        
        auto result = executeVoidRequest("refreshGitHubTokens", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("refresh_github_tokens", true, currentUser->email);
        } else {
            logAuthOperation("refresh_github_tokens", false, currentUser->email, result.error().message);
        }
        
        return result;
    }

    AuthResult<std::string> getGitHubAccessToken() {
        if (!currentUser) {
            logAuthOperation("get_github_token", false, "", "No user signed in");
            return AuthResult<std::string>(AuthError{AuthErrorCode::UserNotFound,
                                                   "No authenticated user",
                                                   "Must be signed in to get GitHub access token",
                                                   "GitHubAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["provider"] = "github.com";
        
        auto headers = getAuthHeaders();
        auto response = networkManager->post(buildUrl("getGitHubToken"), requestBody.dump(), headers);
        
        if (response.statusCode != 200) {
            logAuthOperation("get_github_token", false, currentUser->email, "Failed to get GitHub token");
            return AuthResult<std::string>(parseErrorResponse(response.body));
        }
        
        try {
            auto jsonResponse = nlohmann::json::parse(response.body);
            std::string githubToken = jsonResponse["github_access_token"];
            logAuthOperation("get_github_token", true, currentUser->email);
            return AuthResult<std::string>(githubToken);
        } catch (const std::exception& e) {
            logAuthOperation("get_github_token", false, currentUser->email, e.what());
            return AuthResult<std::string>(AuthError{AuthErrorCode::NetworkError,
                                                   "Failed to parse GitHub token response",
                                                   e.what(),
                                                   "GitHubAuth"});
        }
    }

private:
    std::string extractGitHubUserId() {
        if (!currentUser) return "";
        
        if (currentUser->customClaims.count("github_user_id") > 0) {
            return currentUser->customClaims.at("github_user_id");
        }
        return "";
    }

    std::string extractGitHubUsername() {
        if (!currentUser) return "";
        
        if (currentUser->customClaims.count("github_username") > 0) {
            return currentUser->customClaims.at("github_username");
        }
        
        if (!currentUser->displayName.empty()) {
            return currentUser->displayName;
        }
        
        if (!currentUser->email.empty()) {
            size_t atPos = currentUser->email.find('@');
            if (atPos != std::string::npos) {
                return currentUser->email.substr(0, atPos);
            }
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