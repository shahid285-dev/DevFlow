#ifndef GITHUB_ENGINE_H
#define GITHUB_ENGINE_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class GitHubExtension : public GitBase {
public:
    struct GitHubUser {
        std::string login;
        std::string name;
        std::string email;
        std::string avatar_url;
        std::string type; // "User" or "Organization"
        int64_t id;
        std::string url;
        std::string html_url;
        int followers;
        int following;
        std::string created_at;
        std::string updated_at;
    };

    struct GitHubRepository {
        std::string name;
        std::string full_name;
        std::string description;
        std::string html_url;
        std::string clone_url;
        std::string ssh_url;
        std::string default_branch;
        GitHubUser owner;
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
        nlohmann::json permissions; // admin, push, pull
    };

    struct GitHubIssue {
        int number;
        std::string title;
        std::string body;
        std::string state; // "open", "closed"
        GitHubUser user;
        std::vector<GitHubUser> assignees;
        std::vector<std::string> labels;
        GitHubUser closed_by;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string html_url;
        GitHubRepository repository;
    };

    struct GitHubPullRequest {
        int number;
        std::string title;
        std::string body;
        std::string state; // "open", "closed", "merged"
        std::string head_branch;
        std::string base_branch;
        GitHubUser user;
        GitHubUser merged_by;
        std::vector<GitHubUser> assignees;
        std::vector<std::string> labels;
        std::vector<GitHubUser> requested_reviewers;
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
    };

    struct GitHubRelease {
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
        std::vector<GitHubUser> authors;
        std::vector<std::string> assets;
    };

    struct GitHubWorkflow {
        int64_t id;
        std::string name;
        std::string path;
        std::string state; // "active", "deleted", "disabled_fork", etc.
        std::string created_at;
        std::string updated_at;
        std::string html_url;
        std::string badge_url;
    };

    struct GitHubCodespace {
        std::string id;
        std::string name;
        std::string display_name;
        std::string state; // "Available", "Starting", "ShuttingDown", etc.
        std::string repository_name;
        std::string branch;
        std::string git_status;
        std::string location;
        std::string machine_name;
        std::string created_at;
        std::string last_used_at;
        int retention_period_minutes;
        nlohmann::json devcontainer_config;
    };

    struct GitHubEnvironment {
        std::string name;
        std::string url;
        std::string html_url;
        std::vector<std::string> protection_rules;
        int wait_timer;
        nlohmann::json deployment_branch_policy;
    };

    struct GitHubTeam {
        int64_t id;
        std::string name;
        std::string slug;
        std::string description;
        std::string privacy; // "closed", "secret"
        std::string permission; // "pull", "push", "admin"
        std::vector<GitHubUser> members;
        int members_count;
        int repos_count;
        std::string created_at;
        std::string updated_at;
    };

    struct GitHubWebhook {
        int64_t id;
        std::string name;
        std::vector<std::string> events;
        std::string url;
        bool is_active;
        std::string created_at;
        std::string updated_at;
    };

    struct GitHubActionSecret {
        std::string name;
        std::string created_at;
        std::string updated_at;
    };

    struct GitHubDependency {
        std::string package_name;
        std::string package_manager;
        std::string requirements;
        std::string latest_version;
        std::vector<std::string> vulnerabilities;
    };


    struct GitHubConfig {
        std::string base_url = "https://api.github.com";
        std::string token;
        std::string username;
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
    };


    GitHubExtension(const GitHubConfig& config);
    virtual ~GitHubExtension();

    void set_config(const GitHubConfig& config);
    GitHubConfig get_config() const;


    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();


    GitHubUser get_current_user();
    GitHubUser get_user(const std::string& username);
    std::vector<GitHubUser> list_followers(const std::string& username = "");
    std::vector<GitHubUser> list_following(const std::string& username = "");
    std::vector<GitHubRepository> list_user_repositories(const std::string& username = "");


    GitHubRepository create_repository(const std::string& name, const std::string& description = "", 
                                     bool is_private = true, bool is_template = false);
    GitHubRepository get_repository(const std::string& owner, const std::string& repo);
    std::vector<GitHubRepository> list_organization_repositories(const std::string& org);
    bool delete_repository(const std::string& owner, const std::string& repo);
    GitHubRepository fork_repository(const std::string& owner, const std::string& repo, 
                                   const std::string& organization = "");
    
    void clone_github_repository(const std::string& owner, const std::string& repo, 
                               const std::string& local_path,
                               const std::function<bool(size_t, size_t)>& progress_callback = {});
    void sync_fork(const std::string& upstream_owner, const std::string& upstream_repo);


    struct BranchProtectionRule {
        bool require_pull_request_reviews;
        int required_approving_review_count;
        bool require_code_owner_reviews;
        bool enforce_admins;
        bool require_signed_commits;
        bool require_linear_history;
        bool allow_force_pushes;
        bool allow_deletions;
        std::vector<std::string> required_status_checks;
        bool require_branches_up_to_date;
        std::vector<std::string> restrictions; // user/team restrictions
    };

    void set_branch_protection(const std::string& owner, const std::string& repo, 
                              const std::string& branch, const BranchProtectionRule& rule);
    BranchProtectionRule get_branch_protection(const std::string& owner, const std::string& repo, 
                                              const std::string& branch);
    void delete_branch_protection(const std::string& owner, const std::string& repo, 
                                 const std::string& branch);


    GitHubIssue create_issue(const std::string& owner, const std::string& repo, 
                           const std::string& title, const std::string& body = "",
                           const std::vector<std::string>& assignees = {},
                           const std::vector<std::string>& labels = {});
    GitHubIssue get_issue(const std::string& owner, const std::string& repo, int issue_number);
    std::vector<GitHubIssue> list_issues(const std::string& owner, const std::string& repo,
                                        const std::string& state = "open", 
                                        const std::string& assignee = "",
                                        const std::vector<std::string>& labels = {});
    GitHubIssue update_issue(const std::string& owner, const std::string& repo, int issue_number,
                           const std::string& title = "", const std::string& body = "",
                           const std::string& state = "", 
                           const std::vector<std::string>& assignees = {},
                           const std::vector<std::string>& labels = {});
    bool close_issue(const std::string& owner, const std::string& repo, int issue_number);


    GitHubPullRequest create_pull_request(const std::string& owner, const std::string& repo,
                                        const std::string& title, const std::string& head_branch,
                                        const std::string& base_branch, const std::string& body = "",
                                        bool is_draft = false);
    GitHubPullRequest get_pull_request(const std::string& owner, const std::string& repo, int pr_number);
    std::vector<GitHubPullRequest> list_pull_requests(const std::string& owner, const std::string& repo,
                                                     const std::string& state = "open",
                                                     const std::string& head_branch = "",
                                                     const std::string& base_branch = "");
    GitHubPullRequest update_pull_request(const std::string& owner, const std::string& repo, int pr_number,
                                        const std::string& title = "", const std::string& body = "",
                                        const std::string& state = "", const std::string& base_branch = "");
    bool merge_pull_request(const std::string& owner, const std::string& repo, int pr_number,
                          const std::string& commit_title = "", const std::string& commit_message = "",
                          const std::string& merge_method = "merge"); // merge, squash, rebase


    struct Review {
        int64_t id;
        GitHubUser user;
        std::string body;
        std::string state; // "APPROVED", "CHANGES_REQUESTED", "COMMENTED"
        std::string submitted_at;
        std::string commit_id;
    };

    Review create_review(const std::string& owner, const std::string& repo, int pr_number,
                        const std::string& body, const std::string& event, // "APPROVE", "REQUEST_CHANGES", "COMMENT"
                        const std::vector<std::string>& comments = {});
    std::vector<Review> list_reviews(const std::string& owner, const std::string& repo, int pr_number);
    void dismiss_review(const std::string& owner, const std::string& repo, int pr_number, 
                       int64_t review_id, const std::string& message);


    GitHubRelease create_release(const std::string& owner, const std::string& repo,
                               const std::string& tag_name, const std::string& name = "",
                               const std::string& body = "", bool is_draft = false,
                               bool is_prerelease = false, const std::string& target_commitish = "");
    std::vector<GitHubRelease> list_releases(const std::string& owner, const std::string& repo);
    GitHubRelease get_release_by_tag(const std::string& owner, const std::string& repo, 
                                   const std::string& tag_name);
    bool delete_release(const std::string& owner, const std::string& repo, int64_t release_id);


    struct WorkflowRun {
        int64_t id;
        std::string name;
        std::string head_branch;
        std::string head_sha;
        std::string run_number;
        std::string event;
        std::string status; // "queued", "in_progress", "completed"
        std::string conclusion; // "success", "failure", "cancelled", etc.
        int64_t workflow_id;
        std::string created_at;
        std::string updated_at;
    };

    std::vector<GitHubWorkflow> list_workflows(const std::string& owner, const std::string& repo);
    std::vector<WorkflowRun> list_workflow_runs(const std::string& owner, const std::string& repo,
                                               int64_t workflow_id = 0, const std::string& branch = "");
    WorkflowRun get_workflow_run(const std::string& owner, const std::string& repo, int64_t run_id);
    bool rerun_workflow(const std::string& owner, const std::string& repo, int64_t run_id);
    bool cancel_workflow(const std::string& owner, const std::string& repo, int64_t run_id);
    std::string download_workflow_logs(const std::string& owner, const std::string& repo, int64_t run_id);

    
    std::vector<GitHubActionSecret> list_secrets(const std::string& owner, const std::string& repo);
    void create_or_update_secret(const std::string& owner, const std::string& repo,
                               const std::string& secret_name, const std::string& encrypted_value);
    bool delete_secret(const std::string& owner, const std::string& repo, const std::string& secret_name);


    std::vector<GitHubCodespace> list_codespaces(const std::string& owner = "", const std::string& repo = "");
    GitHubCodespace get_codespace(const std::string& codespace_name);
    GitHubCodespace create_codespace(const std::string& owner, const std::string& repo,
                                   const std::string& branch = "", const std::string& location = "",
                                   const std::string& machine_type = "");
    bool delete_codespace(const std::string& codespace_name);
    bool start_codespace(const std::string& codespace_name);
    bool stop_codespace(const std::string& codespace_name);
    std::string get_codespace_export(const std::string& codespace_name);

    
    struct GitHubPackage {
        std::string name;
        std::string package_type; // npm, maven, docker, etc.
        std::string visibility; // public, private, internal
        std::string created_at;
        std::string updated_at;
        int64_t version_count;
        nlohmann::json registry; // package registry details
    };

    std::vector<GitHubPackage> list_packages(const std::string& owner, 
                                           const std::string& package_type = "");
    GitHubPackage get_package(const std::string& owner, const std::string& package_type,
                            const std::string& package_name);
    bool delete_package(const std::string& owner, const std::string& package_type,
                       const std::string& package_name);
    bool restore_package(const std::string& owner, const std::string& package_type,
                        const std::string& package_name);

    
    struct SecurityVulnerability {
        std::string package_name;
        std::string severity; // "low", "medium", "high", "critical"
        std::string vulnerable_version_range;
        std::string first_patched_version;
        std::string advisory_url;
        std::string summary;
        std::string published_at;
    };

    std::vector<SecurityVulnerability> get_vulnerability_alerts(const std::string& owner, 
                                                               const std::string& repo);
    bool enable_vulnerability_alerts(const std::string& owner, const std::string& repo);
    bool disable_vulnerability_alerts(const std::string& owner, const std::string& repo);


    struct DependabotAlert {
        int64_t number;
        std::string state; // "dismissed", "fixed", "open"
        SecurityVulnerability vulnerability;
        std::string dependency;
        std::string manifest_path;
        std::string created_at;
        std::string updated_at;
        std::string dismissed_at;
        GitHubUser dismissed_by;
        std::string dismissal_reason;
    };

    std::vector<DependabotAlert> list_dependabot_alerts(const std::string& owner, 
                                                       const std::string& repo);
    DependabotAlert get_dependabot_alert(const std::string& owner, const std::string& repo, 
                                        int64_t alert_number);
    bool update_dependabot_alert(const std::string& owner, const std::string& repo,
                                int64_t alert_number, const std::string& state,
                                const std::string& dismissal_reason = "");


    GitHubWebhook create_webhook(const std::string& owner, const std::string& repo,
                               const std::string& url, const std::vector<std::string>& events,
                               const std::string& secret = "");
    std::vector<GitHubWebhook> list_webhooks(const std::string& owner, const std::string& repo);
    GitHubWebhook get_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);
    bool delete_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);


    std::vector<GitHubTeam> list_teams(const std::string& owner, const std::string& repo);
    void add_team_to_repository(const std::string& owner, const std::string& repo,
                               const std::string& team_slug, const std::string& permission);
    void remove_team_from_repository(const std::string& owner, const std::string& repo,
                                   const std::string& team_slug);
    std::vector<GitHubUser> list_collaborators(const std::string& owner, const std::string& repo);
    void add_collaborator(const std::string& owner, const std::string& repo,
                         const std::string& username, const std::string& permission);
    void remove_collaborator(const std::string& owner, const std::string& repo,
                           const std::string& username);

    struct GitHubPages {
        std::string url;
        std::string status; // "built", "building", "errored"
        std::string cname;
        bool is_https;
        std::string source_branch;
        std::string source_path;
        std::string published_at;
    };

    GitHubPages get_pages_info(const std::string& owner, const std::string& repo);
    bool enable_pages(const std::string& owner, const std::string& repo,
                     const std::string& source_branch, const std::string& source_path = "/");
    bool disable_pages(const std::string& owner, const std::string& repo);


    struct Discussion {
        int64_t number;
        std::string title;
        std::string body;
        GitHubUser user;
        std::string category;
        std::string state; // "open", "locked", "converting", "transferring"
        int answer_chosen_at;
        GitHubUser answer_chosen_by;
        int comments_count;
        std::string created_at;
        std::string updated_at;
    };

    std::vector<Discussion> list_discussions(const std::string& owner, const std::string& repo,
                                            const std::string& category = "");
    Discussion get_discussion(const std::string& owner, const std::string& repo, int64_t discussion_number);
    Discussion create_discussion(const std::string& owner, const std::string& repo,
                               const std::string& title, const std::string& body,
                               const std::string& category);


    struct Project {
        int64_t id;
        std::string name;
        std::string body;
        std::string state; // "open", "closed"
        std::string created_at;
        std::string updated_at;
        int number;
        std::string html_url;
    };

    std::vector<Project> list_projects(const std::string& owner, const std::string& repo);
    Project create_project(const std::string& owner, const std::string& repo,
                          const std::string& name, const std::string& body = "");
    bool delete_project(int64_t project_id);


    struct SearchResult {
        int total_count;
        bool incomplete_results;
        nlohmann::json items;
    };

    SearchResult search_repositories(const std::string& query, const std::string& sort = "",
                                   const std::string& order = "desc", int per_page = 30);
    SearchResult search_code(const std::string& query, const std::string& owner = "",
                           const std::string& repo = "", const std::string& language = "");
    SearchResult search_issues(const std::string& query, const std::string& owner = "",
                             const std::string& repo = "", const std::string& state = "");


    struct Gist {
        std::string id;
        std::string description;
        bool is_public;
        GitHubUser owner;
        std::map<std::string, nlohmann::json> files;
        std::string created_at;
        std::string updated_at;
        int comments;
        std::string html_url;
        std::string git_pull_url;
        std::string git_push_url;
    };

    Gist create_gist(const std::string& description, const std::map<std::string, std::string>& files,
                    bool is_public = false);
    Gist get_gist(const std::string& gist_id);
    std::vector<Gist> list_user_gists(const std::string& username = "");
    bool delete_gist(const std::string& gist_id);


    struct EnterpriseLicense {
        int seats;
        int seats_used;
        int seats_available;
        std::string kind;
        std::string expires_at;
    };

    EnterpriseLicense get_enterprise_license(const std::string& enterprise);
    std::vector<GitHubUser> list_enterprise_users(const std::string& enterprise);

    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    GitHubConfig config_;
    std::mutex api_mutex_;
    std::map<std::string, nlohmann::json> cache_;
    
    std::string make_request(const std::string& method, const std::string& url, 
                           const std::string& data = "");
    void handle_http_error(int status_code, const std::string& response);
    void update_rate_limits(const std::string& response_headers);
    
    void cache_set(const std::string& key, const nlohmann::json& value);
    std::optional<nlohmann::json> cache_get(const std::string& key);
    void cache_clear();
    
    struct RateLimit {
        int limit;
        int remaining;
        int reset_time;
    };
    
    std::map<std::string, RateLimit> rate_limits_;
    GitHubUser user_from_json(const nlohmann::json& json);
    GitHubRepository repository_from_json(const nlohmann::json& json);
    GitHubIssue issue_from_json(const nlohmann::json& json);
    GitHubPullRequest pull_request_from_json(const nlohmann::json& json);
    GitHubRelease release_from_json(const nlohmann::json& json);
    GitHubCodespace codespace_from_json(const nlohmann::json& json);
};

#endif 