#pragma once

#include "BaseAuth.h"
#include <regex>
#include "DatabaseEngine.h"
#include "MetricsEngine.h"

namespace Auth {

class EmailPasswordAuth : public BaseAuth {
private:
    static constexpr size_t MIN_PASSWORD_LENGTH = 8;
    static constexpr size_t MAX_PASSWORD_LENGTH = 128;
    
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
        userTable.columns.emplace_back("access_token", "TEXT");
        userTable.columns.emplace_back("refresh_token", "TEXT");
        userTable.columns.emplace_back("token_expiration", "INTEGER");
        userTable.columns.emplace_back("created_at", "INTEGER");
        userTable.columns.emplace_back("last_login_at", "INTEGER");
        userTable.columns.emplace_back("custom_claims", "TEXT");
        
        databaseEngine->createTable(userTable);
    }

    bool storeUserLocally(const AuthUser& user) {
        if (!databaseEngine) return false;
        
        std::unordered_map<std::string, std::string> userData;
        userData["uid"] = user.uid;
        userData["email"] = user.email;
        userData["display_name"] = user.displayName;
        userData["photo_url"] = user.photoURL;
        userData["phone_number"] = user.phoneNumber;
        userData["email_verified"] = user.emailVerified ? "1" : "0";
        userData["access_token"] = user.accessToken;
        userData["refresh_token"] = user.refreshToken;
        userData["token_expiration"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.tokenExpiration.time_since_epoch()).count());
        userData["created_at"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.createdAt.time_since_epoch()).count());
        userData["last_login_at"] = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
            user.lastLoginAt.time_since_epoch()).count());
        
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
        data["provider"] = "email_password";
        if (!email.empty()) data["email"] = email;
        if (!error.empty()) data["error"] = error;
        
        if (success) {
            metricsEngine->logInfo("EMAIL_PASSWORD_AUTH", operation, "Email/password authentication operation completed", data);
        } else {
            metricsEngine->logError("EMAIL_PASSWORD_AUTH", operation, "Email/password authentication operation failed", 0, data);
        }
    }

    AuthResult<void> validateEmail(std::string_view email) {
        if (email.empty()) {
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                            "Email cannot be empty",
                                            "Please provide an email address",
                                            "EmailPasswordAuth"});
        }
        
        static const std::regex emailRegex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
        if (!std::regex_match(std::string(email), emailRegex)) {
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                            "Invalid email format",
                                            "Please provide a valid email address",
                                            "EmailPasswordAuth"});
        }
        
        return AuthResult<void>();
    }

    AuthResult<void> validatePassword(const secure_string& password) {
        if (password.empty()) {
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                            "Password cannot be empty",
                                            "Please provide a password",
                                            "EmailPasswordAuth"});
        }
        
        if (password.size() < MIN_PASSWORD_LENGTH) {
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                            "Password too short",
                                            "Password must be at least " + 
                                            std::to_string(MIN_PASSWORD_LENGTH) + 
                                            " characters long",
                                            "EmailPasswordAuth"});
        }
        
        if (password.size() > MAX_PASSWORD_LENGTH) {
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                            "Password too long",
                                            "Password must be no more than " + 
                                            std::to_string(MAX_PASSWORD_LENGTH) + 
                                            " characters long",
                                            "EmailPasswordAuth"});
        }
        
        return AuthResult<void>();
    }

    AuthResult<void> validateEmailAndPassword(std::string_view email, const secure_string& password) {
        auto emailResult = validateEmail(email);
        if (emailResult.isError()) {
            return emailResult;
        }
        
        auto passwordResult = validatePassword(password);
        if (passwordResult.isError()) {
            return passwordResult;
        }
        
        return AuthResult<void>();
    }

public:
    EmailPasswordAuth(std::string_view key, 
                     std::string_view domain,
                     std::string_view apiBaseUrl,
                     std::shared_ptr<NetworkManager> netManager,
                     std::shared_ptr<TokenManager> tokenMgr,
                     std::shared_ptr<DatabaseEngine> dbEngine = nullptr,
                     std::shared_ptr<metrics::MetricsEngine> metricsEng = nullptr)
        : BaseAuth(key, domain, apiBaseUrl, std::move(netManager), std::move(tokenMgr))
        , databaseEngine(std::move(dbEngine))
        , metricsEngine(std::move(metricsEng))
        , userTableName("auth_users") {
        
        configureEndpoint("signIn", "signInWithPassword");
        configureEndpoint("signUp", "signUp");
        configureEndpoint("updateEmail", "updateEmail");
        configureEndpoint("updatePassword", "updatePassword");
        configureEndpoint("sendResetEmail", "sendPasswordResetEmail");
        configureEndpoint("confirmReset", "resetPassword");
        configureEndpoint("verifyEmail", "verifyEmail");
        
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
                     "Use signInWithEmailPassword instead",
                     "Email/password provider requires email and password",
                     "EmailPasswordAuth"});
    }

    AuthResult<std::unique_ptr<AuthUser>> signInWithEmailPassword(std::string_view email, secure_string&& password) {
        auto validationResult = validateEmailAndPassword(email, password);
        if (validationResult.isError()) {
            logAuthOperation("signin_email_password", false, std::string(email), validationResult.error().message);
            return AuthResult<std::unique_ptr<AuthUser>>(validationResult.error());
        }
        
        nlohmann::json requestBody;
        requestBody["email"] = std::string(email);
        requestBody["password"] = std::string(password.c_str());
        requestBody["returnSecureToken"] = true;
        
        auto result = executeRequest("signIn", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                storeUserLocally(*currentUser);
            }
            logAuthOperation("signin_email_password", true, std::string(email));
        } else {
            logAuthOperation("signin_email_password", false, std::string(email), result.error().message);
        }
        
        return result;
    }
    
    AuthResult<std::unique_ptr<AuthUser>> signUp() override {
        return AuthResult<std::unique_ptr<AuthUser>>(
            AuthError{AuthErrorCode::InvalidCredential,
                     "Use signUpWithEmailPassword instead",
                     "Email/password provider requires email and password",
                     "EmailPasswordAuth"});
    }

    AuthResult<std::unique_ptr<AuthUser>> signUpWithEmailPassword(std::string_view email, secure_string&& password, const UserProfileChangeRequest& profile = {}) {
        auto validationResult = validateEmailAndPassword(email, password);
        if (validationResult.isError()) {
            logAuthOperation("signup_email_password", false, std::string(email), validationResult.error().message);
            return AuthResult<std::unique_ptr<AuthUser>>(validationResult.error());
        }
        
        nlohmann::json requestBody;
        requestBody["email"] = std::string(email);
        requestBody["password"] = std::string(password.c_str());
        requestBody["returnSecureToken"] = true;
        
        if (profile.displayName.has_value()) {
            requestBody["displayName"] = profile.displayName.value();
        }
        
        auto result = executeRequest("signUp", requestBody);
        
        if (result.isSuccess()) {
            if (databaseEngine) {
                storeUserLocally(*currentUser);
            }
            logAuthOperation("signup_email_password", true, std::string(email));
        } else {
            logAuthOperation("signup_email_password", false, std::string(email), result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> signOut() override {
        if (!currentUser) {
            logAuthOperation("signout", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to sign out",
                                            "EmailPasswordAuth"});
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
        return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                        "Cannot link email/password provider",
                                        "Email/password is a primary authentication method",
                                        "EmailPasswordAuth"});
    }
    
    AuthResult<void> unlinkAccount() override {
        return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                        "Cannot unlink email/password provider",
                                        "Email/password is a primary authentication method",
                                        "EmailPasswordAuth"});
    }
    
    AuthResult<void> reauthenticate() override {
        return AuthResult<void>(AuthError{AuthErrorCode::InvalidCredential,
                                        "Use reauthenticateWithEmailPassword instead",
                                        "Email/password provider requires credentials for reauthentication",
                                        "EmailPasswordAuth"});
    }

    AuthResult<void> reauthenticateWithEmailPassword(std::string_view email, secure_string&& password) {
        if (!currentUser) {
            logAuthOperation("reauthenticate_email_password", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to reauthenticate",
                                            "EmailPasswordAuth"});
        }
        
        auto validationResult = validateEmailAndPassword(email, password);
        if (validationResult.isError()) {
            logAuthOperation("reauthenticate_email_password", false, std::string(email), validationResult.error().message);
            return AuthResult<void>(validationResult.error());
        }
        
        nlohmann::json requestBody;
        requestBody["email"] = std::string(email);
        requestBody["password"] = std::string(password.c_str());
        
        auto result = executeVoidRequest("reauthenticate", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("reauthenticate_email_password", true, std::string(email));
        } else {
            logAuthOperation("reauthenticate_email_password", false, std::string(email), result.error().message);
        }
        
        return result;
    }

    AuthResult<void> updateProfile(const UserProfileChangeRequest& request) override {
        if (!currentUser) {
            logAuthOperation("update_profile", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to update profile",
                                            "EmailPasswordAuth"});
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
                                                   "EmailPasswordAuth"});
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
                                            "EmailPasswordAuth"});
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

    AuthResult<void> updateEmail(std::string_view newEmail) {
        if (!currentUser) {
            logAuthOperation("update_email", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to update email",
                                            "EmailPasswordAuth"});
        }
        
        auto validationResult = validateEmail(newEmail);
        if (validationResult.isError()) {
            logAuthOperation("update_email", false, currentUser->email, validationResult.error().message);
            return AuthResult<void>(validationResult.error());
        }
        
        nlohmann::json requestBody;
        requestBody["email"] = std::string(newEmail);
        
        auto result = executeVoidRequest("updateEmail", requestBody);
        
        if (result.isSuccess()) {
            std::string oldEmail = currentUser->email;
            currentUser->email = std::string(newEmail);
            
            if (databaseEngine) {
                updateLocalUserData(*currentUser);
            }
            logAuthOperation("update_email", true, oldEmail);
        } else {
            logAuthOperation("update_email", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> updatePassword(secure_string&& newPassword) {
        if (!currentUser) {
            logAuthOperation("update_password", false, "", "No user signed in");
            return AuthResult<void>(AuthError{AuthErrorCode::UserNotFound,
                                            "No authenticated user",
                                            "Must be signed in to update password",
                                            "EmailPasswordAuth"});
        }
        
        auto validationResult = validatePassword(newPassword);
        if (validationResult.isError()) {
            logAuthOperation("update_password", false, currentUser->email, validationResult.error().message);
            return AuthResult<void>(validationResult.error());
        }
        
        nlohmann::json requestBody;
        requestBody["password"] = std::string(newPassword.c_str());
        
        auto result = executeVoidRequest("updatePassword", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("update_password", true, currentUser->email);
        } else {
            logAuthOperation("update_password", false, currentUser->email, result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> sendPasswordResetEmail(std::string_view email, const ActionCodeSettings& settings = {}) {
        auto validationResult = validateEmail(email);
        if (validationResult.isError()) {
            logAuthOperation("send_password_reset", false, std::string(email), validationResult.error().message);
            return AuthResult<void>(validationResult.error());
        }
        
        nlohmann::json requestBody;
        requestBody["email"] = std::string(email);
        requestBody["requestType"] = "PASSWORD_RESET";
        
        if (!settings.url.empty()) {
            requestBody["continueUrl"] = settings.url;
        }
        if (settings.handleCodeInApp) {
            requestBody["canHandleCodeInApp"] = true;
        }
        
        auto result = executeVoidRequest("sendResetEmail", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("send_password_reset", true, std::string(email));
        } else {
            logAuthOperation("send_password_reset", false, std::string(email), result.error().message);
        }
        
        return result;
    }
    
    AuthResult<void> confirmPasswordReset(std::string_view resetCode, secure_string&& newPassword) {
        auto validationResult = validatePassword(newPassword);
        if (validationResult.isError()) {
            logAuthOperation("confirm_password_reset", false, "", validationResult.error().message);
            return AuthResult<void>(validationResult.error());
        }
        
        if (resetCode.empty()) {
            logAuthOperation("confirm_password_reset", false, "", "Empty reset code");
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidToken,
                                            "Reset code cannot be empty",
                                            "Please provide a valid reset code",
                                            "EmailPasswordAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["oobCode"] = std::string(resetCode);
        requestBody["newPassword"] = std::string(newPassword.c_str());
        
        auto result = executeVoidRequest("confirmReset", requestBody);
        
        if (result.isSuccess()) {
            logAuthOperation("confirm_password_reset", true);
        } else {
            logAuthOperation("confirm_password_reset", false, "", result.error().message);
        }
        
        return result;
    }

    AuthResult<void> verifyEmail(std::string_view verificationCode) {
        if (verificationCode.empty()) {
            logAuthOperation("verify_email", false, "", "Empty verification code");
            return AuthResult<void>(AuthError{AuthErrorCode::InvalidToken,
                                            "Verification code cannot be empty",
                                            "Please provide a valid verification code",
                                            "EmailPasswordAuth"});
        }
        
        nlohmann::json requestBody;
        requestBody["oobCode"] = std::string(verificationCode);
        
        auto result = executeVoidRequest("verifyEmail", requestBody);
        
        if (result.isSuccess() && currentUser) {
            currentUser->emailVerified = true;
            if (databaseEngine) {
                updateLocalUserData(*currentUser);
            }
            logAuthOperation("verify_email", true, currentUser->email);
        } else {
            logAuthOperation("verify_email", false, currentUser ? currentUser->email : "", result.error().message);
        }
        
        return result;
    }

private:
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