#ifndef CUSTOM_PROVIDER_EXTENSION_H
#define CUSTOM_PROVIDER_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class CustomProviderExtension : public GitBase {
public:
    // Generic data structures that work across providers
    struct GenericUser {
        std::string id;
        std::string login;
        std::string name;
        std::string email;
        std::string avatar_url;
        std::string html_url;
        std::string type; // "user", "organization", "bot"
        std::string created_at;
        std::string updated_at;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    struct GenericRepository {
        std::string id;
        std::string name;
        std::string full_name;
        std::string description;
        std::string html_url;
        std::string clone_url;
        std::string ssh_url;
        std::string default_branch;
        GenericUser owner;
        bool is_private;
        bool is_fork;
        bool is_archived;
        bool is_template;
        int forks_count;
        int stargazers_count;
        int watchers_count;
        int open_issues_count;
        std::string created_at;
        std::string updated_at;
        std::string pushed_at;
        std::string language;
        nlohmann::json permissions;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    struct GenericIssue {
        std::string id;
        std::string number;
        std::string title;
        std::string body;
        std::string state; // "open", "closed"
        GenericUser user;
        std::vector<GenericUser> assignees;
        std::vector<std::string> labels;
        GenericUser closed_by;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string html_url;
        GenericRepository repository;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    struct GenericPullRequest {
        std::string id;
        std::string number;
        std::string title;
        std::string body;
        std::string state; // "open", "closed", "merged"
        std::string head_branch;
        std::string base_branch;
        GenericUser user;
        GenericUser merged_by;
        std::vector<GenericUser> assignees;
        std::vector<std::string> labels;
        std::vector<GenericUser> requested_reviewers;
        bool is_draft;
        bool is_merged;
        std::string merge_commit_sha;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string merged_at;
        std::string html_url;
        int additions;
        int deletions;
        int changed_files;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    struct GenericCommit {
        std::string sha;
        std::string html_url;
        GenericUser author;
        GenericUser committer;
        std::string message;
        std::vector<std::string> parents;
        std::string created_at;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    struct GenericBranch {
        std::string name;
        GenericCommit commit;
        bool protected;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    struct GenericRelease {
        std::string id;
        std::string tag_name;
        std::string name;
        std::string body;
        bool is_draft;
        bool is_prerelease;
        std::string target_commitish;
        std::string created_at;
        std::string published_at;
        std::string html_url;
        std::string tarball_url;
        std::string zipball_url;
        std::vector<GenericUser> authors;
        nlohmann::json raw_data; // Provider-specific raw data
    };

    // Provider configuration with flexible endpoint mapping
    struct ProviderConfig {
        std::string base_url;
        std::string api_version = "v1";
        std::string auth_type = "token"; // "token", "basic", "oauth", "none"
        std::string token;
        std::string username;
        std::string password;
        std::string custom_auth_header;
        
        // Endpoint mapping - users can customize these for their provider
        std::map<std::string, std::string> endpoints = {
            // User endpoints
            {"get_current_user", "/user"},
            {"get_user", "/users/{username}"},
            {"list_user_repos", "/users/{username}/repos"},
            
            // Repository endpoints
            {"get_repo", "/repos/{owner}/{repo}"},
            {"list_org_repos", "/orgs/{org}/repos"},
            {"create_repo", "/user/repos"},
            {"fork_repo", "/repos/{owner}/{repo}/forks"},
            {"delete_repo", "/repos/{owner}/{repo}"},
            
            // Issue endpoints
            {"get_issue", "/repos/{owner}/{repo}/issues/{number}"},
            {"list_issues", "/repos/{owner}/{repo}/issues"},
            {"create_issue", "/repos/{owner}/{repo}/issues"},
            {"update_issue", "/repos/{owner}/{repo}/issues/{number}"},
            
            // Pull request endpoints
            {"get_pull", "/repos/{owner}/{repo}/pulls/{number}"},
            {"list_pulls", "/repos/{owner}/{repo}/pulls"},
            {"create_pull", "/repos/{owner}/{repo}/pulls"},
            {"update_pull", "/repos/{owner}/{repo}/pulls/{number}"},
            {"merge_pull", "/repos/{owner}/{repo}/pulls/{number}/merge"},
            
            // Branch endpoints
            {"get_branch", "/repos/{owner}/{repo}/branches/{branch}"},
            {"list_branches", "/repos/{owner}/{repo}/branches"},
            
            // Commit endpoints
            {"get_commit", "/repos/{owner}/{repo}/commits/{sha}"},
            {"list_commits", "/repos/{owner}/{repo}/commits"},
            
            // Release endpoints
            {"get_release", "/repos/{owner}/{repo}/releases/{id}"},
            {"list_releases", "/repos/{owner}/{repo}/releases"},
            {"create_release", "/repos/{owner}/{repo}/releases"}
        };
        
        // Field mapping - map provider-specific fields to generic fields
        std::map<std::string, std::string> field_mapping = {
            // User fields
            {"user.id", "id"},
            {"user.login", "login"},
            {"user.name", "name"},
            {"user.email", "email"},
            {"user.avatar_url", "avatar_url"},
            {"user.html_url", "html_url"},
            {"user.created_at", "created_at"},
            
            // Repository fields
            {"repo.id", "id"},
            {"repo.name", "name"},
            {"repo.full_name", "full_name"},
            {"repo.description", "description"},
            {"repo.html_url", "html_url"},
            {"repo.clone_url", "clone_url"},
            {"repo.ssh_url", "ssh_url"},
            {"repo.default_branch", "default_branch"},
            {"repo.private", "private"},
            {"repo.fork", "fork"},
            {"repo.created_at", "created_at"},
            {"repo.updated_at", "updated_at"},
            {"repo.pushed_at", "pushed_at"},
            {"repo.forks_count", "forks_count"},
            {"repo.stargazers_count", "stargazers_count"},
            {"repo.watchers_count", "watchers_count"},
            {"repo.open_issues_count", "open_issues_count"},
            
            // Issue fields
            {"issue.id", "id"},
            {"issue.number", "number"},
            {"issue.title", "title"},
            {"issue.body", "body"},
            {"issue.state", "state"},
            {"issue.created_at", "created_at"},
            {"issue.updated_at", "updated_at"},
            {"issue.closed_at", "closed_at"},
            {"issue.html_url", "html_url"},
            
            // Pull request fields
            {"pull.id", "id"},
            {"pull.number", "number"},
            {"pull.title", "title"},
            {"pull.body", "body"},
            {"pull.state", "state"},
            {"pull.head_branch", "head.ref"},
            {"pull.base_branch", "base.ref"},
            {"pull.draft", "draft"},
            {"pull.merged", "merged"},
            {"pull.merge_commit_sha", "merge_commit_sha"},
            {"pull.created_at", "created_at"},
            {"pull.updated_at", "updated_at"},
            {"pull.merged_at", "merged_at"},
            {"pull.html_url", "html_url"},
            {"pull.additions", "additions"},
            {"pull.deletions", "deletions"},
            {"pull.changed_files", "changed_files"},
            
            // Commit fields
            {"commit.sha", "sha"},
            {"commit.html_url", "html_url"},
            {"commit.message", "commit.message"},
            {"commit.created_at", "commit.author.date"},
            
            // Branch fields
            {"branch.name", "name"},
            {"branch.protected", "protected"},
            
            // Release fields
            {"release.id", "id"},
            {"release.tag_name", "tag_name"},
            {"release.name", "name"},
            {"release.body", "body"},
            {"release.draft", "draft"},
            {"release.prerelease", "prerelease"},
            {"release.created_at", "created_at"},
            {"release.published_at", "published_at"},
            {"release.html_url", "html_url"}
        };
        
        // Response adapters for custom parsing
        std::function<nlohmann::json(const nlohmann::json&)> user_adapter;
        std::function<nlohmann::json(const nlohmann::json&)> repo_adapter;
        std::function<nlohmann::json(const nlohmann::json&)> issue_adapter;
        std::function<nlohmann::json(const nlohmann::json&)> pull_adapter;
        std::function<nlohmann::json(const nlohmann::json&)> commit_adapter;
        std::function<nlohmann::json(const nlohmann::json&)> branch_adapter;
        std::function<nlohmann::json(const nlohmann::json&)> release_adapter;
        
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
        bool verify_ssl = true;
        std::string user_agent = "CustomGitProvider/1.0";
    };

    // Constructor & Configuration
    CustomProviderExtension(const ProviderConfig& config);
    virtual ~CustomProviderExtension();

    void set_config(const ProviderConfig& config);
    ProviderConfig get_config() const;
    void update_endpoint(const std::string& endpoint_name, const std::string& endpoint_path);
    void update_field_mapping(const std::string& field_path, const std::string& provider_field);
    void set_response_adapter(const std::string& adapter_type, 
                            std::function<nlohmann::json(const nlohmann::json&)> adapter);

    // Authentication & Connection
    bool authenticate();
    bool test_connection();
    std::string get_provider_info();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    // User Management
    GenericUser get_current_user();
    GenericUser get_user(const std::string& username);
    std::vector<GenericUser> list_user_repositories(const std::string& username = "");
    std::vector<GenericUser> list_followers(const std::string& username = "");
    std::vector<GenericUser> list_following(const std::string& username = "");

    // Repository Management
    GenericRepository create_repository(const std::string& name, const std::string& description = "", 
                                      bool is_private = true, const nlohmann::json& additional_params = {});
    GenericRepository get_repository(const std::string& owner, const std::string& repo);
    std::vector<GenericRepository> list_organization_repositories(const std::string& org);
    bool delete_repository(const std::string& owner, const std::string& repo);
    GenericRepository fork_repository(const std::string& owner, const std::string& repo, 
                                    const std::string& organization = "");
    
    // Repository Operations
    void clone_repository(const std::string& owner, const std::string& repo, 
                         const std::string& local_path,
                         const std::function<bool(size_t, size_t)>& progress_callback = {});

    // Branch Management
    GenericBranch get_branch(const std::string& owner, const std::string& repo, const std::string& branch);
    std::vector<GenericBranch> list_branches(const std::string& owner, const std::string& repo);
    GenericBranch create_branch(const std::string& owner, const std::string& repo,
                              const std::string& branch_name, const std::string& from_branch);
    bool delete_branch(const std::string& owner, const std::string& repo, const std::string& branch);

    // Issues Management
    GenericIssue create_issue(const std::string& owner, const std::string& repo, 
                            const std::string& title, const std::string& body = "",
                            const std::vector<std::string>& assignees = {},
                            const std::vector<std::string>& labels = {},
                            const nlohmann::json& additional_params = {});
    GenericIssue get_issue(const std::string& owner, const std::string& repo, const std::string& issue_number);
    std::vector<GenericIssue> list_issues(const std::string& owner, const std::string& repo,
                                         const std::string& state = "open",
                                         const std::vector<std::string>& labels = {},
                                         const nlohmann::json& additional_params = {});
    GenericIssue update_issue(const std::string& owner, const std::string& repo, const std::string& issue_number,
                            const std::string& title = "", const std::string& body = "",
                            const std::string& state = "", 
                            const std::vector<std::string>& assignees = {},
                            const std::vector<std::string>& labels = {},
                            const nlohmann::json& additional_params = {});
    bool close_issue(const std::string& owner, const std::string& repo, const std::string& issue_number);

    // Pull Request Management
    GenericPullRequest create_pull_request(const std::string& owner, const std::string& repo,
                                         const std::string& title, const std::string& head_branch,
                                         const std::string& base_branch, const std::string& body = "",
                                         bool is_draft = false, const std::vector<std::string>& assignees = {},
                                         const std::vector<std::string>& labels = {},
                                         const nlohmann::json& additional_params = {});
    GenericPullRequest get_pull_request(const std::string& owner, const std::string& repo, const std::string& pr_number);
    std::vector<GenericPullRequest> list_pull_requests(const std::string& owner, const std::string& repo,
                                                      const std::string& state = "open",
                                                      const std::string& head_branch = "",
                                                      const std::string& base_branch = "",
                                                      const nlohmann::json& additional_params = {});
    GenericPullRequest update_pull_request(const std::string& owner, const std::string& repo, const std::string& pr_number,
                                         const std::string& title = "", const std::string& body = "",
                                         const std::string& state = "", const std::string& base_branch = "",
                                         const std::vector<std::string>& assignees = {},
                                         const std::vector<std::string>& labels = {},
                                         const nlohmann::json& additional_params = {});
    bool merge_pull_request(const std::string& owner, const std::string& repo, const std::string& pr_number,
                          const std::string& commit_title = "", const std::string& commit_message = "",
                          const std::string& merge_method = "merge", 
                          const nlohmann::json& additional_params = {});

    // Commits Management
    GenericCommit get_commit(const std::string& owner, const std::string& repo, const std::string& sha);
    std::vector<GenericCommit> list_commits(const std::string& owner, const std::string& repo,
                                          const std::string& sha = "", const std::string& path = "",
                                          const std::string& since = "", const std::string& until = "",
                                          const nlohmann::json& additional_params = {});

    // Releases Management
    GenericRelease create_release(const std::string& owner, const std::string& repo,
                                const std::string& tag_name, const std::string& name = "",
                                const std::string& body = "", bool is_draft = false,
                                bool is_prerelease = false, const std::string& target_commitish = "",
                                const nlohmann::json& additional_params = {});
    std::vector<GenericRelease> list_releases(const std::string& owner, const std::string& repo);
    GenericRelease get_release(const std::string& owner, const std::string& repo, const std::string& release_id);
    GenericRelease get_release_by_tag(const std::string& owner, const std::string& repo, 
                                    const std::string& tag_name);
    bool delete_release(const std::string& owner, const std::string& repo, const std::string& release_id);

    // Raw API Access - for provider-specific operations
    nlohmann::json raw_api_get(const std::string& endpoint, const nlohmann::json& params = {});
    nlohmann::json raw_api_post(const std::string& endpoint, const nlohmann::json& data = {});
    nlohmann::json raw_api_put(const std::string& endpoint, const nlohmann::json& data = {});
    nlohmann::json raw_api_patch(const std::string& endpoint, const nlohmann::json& data = {});
    nlohmann::json raw_api_delete(const std::string& endpoint);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    std::string resolve_endpoint(const std::string& endpoint_name, 
                                const std::map<std::string, std::string>& params = {}) const;
    nlohmann::json transform_response(const nlohmann::json& raw_response, const std::string& resource_type);

    // Provider Discovery
    bool detect_provider_type();
    std::string get_detected_provider() const;
    std::vector<std::string> get_supported_operations() const;

private:
    ProviderConfig config_;
    std::mutex api_mutex_;
    std::map<std::string, nlohmann::json> cache_;
    std::string detected_provider_;
    
    // HTTP client implementation
    std::string make_request(const std::string& method, const std::string& url, 
                           const std::string& data = "", const nlohmann::json& headers = {});
    void handle_http_error(int status_code, const std::string& response);
    nlohmann::json parse_json_response(const std::string& response);
    
    // Cache management
    void cache_set(const std::string& key, const nlohmann::json& value);
    std::optional<nlohmann::json> cache_get(const std::string& key);
    void cache_clear();
    
    // Rate limiting
    struct RateLimit {
        int limit;
        int remaining;
        int reset_time;
    };
    
    std::map<std::string, RateLimit> rate_limits_;
    
    // Field mapping and transformation
    std::string map_field(const std::string& field_path) const;
    nlohmann::json extract_field(const nlohmann::json& data, const std::string& field_path) const;
    nlohmann::json apply_field_mapping(const nlohmann::json& data, const std::string& resource_type) const;
    
    // Helper methods for data conversion
    GenericUser user_from_json(const nlohmann::json& json);
    GenericRepository repository_from_json(const nlohmann::json& json);
    GenericIssue issue_from_json(const nlohmann::json& json);
    GenericPullRequest pull_request_from_json(const nlohmann::json& json);
    GenericCommit commit_from_json(const nlohmann::json& json);
    GenericBranch branch_from_json(const nlohmann::json& json);
    GenericRelease release_from_json(const nlohmann::json& json);
    
    std::string replace_template_variables(const std::string& template_str, 
                                         const std::map<std::string, std::string>& variables) const;
    
    std::map<std::string, std::string> get_auth_headers() const;

    void auto_detect_provider(const nlohmann::json& response);
};

#endif // CUSTOM_PROVIDER_EXTENSION_H