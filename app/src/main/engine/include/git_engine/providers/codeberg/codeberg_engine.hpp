#ifndef CODEBERG_EXTENSION_H
#define CODEBERG_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class CodebergExtension : public GitBase {
public:
    struct CodebergUser {
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
        std::string location;
        std::string website;
        std::string bio;
        bool is_admin;
    };

    struct CodebergRepository {
        std::string name;
        std::string full_name;
        std::string description;
        std::string html_url;
        std::string clone_url;
        std::string ssh_url;
        std::string default_branch;
        CodebergUser owner;
        bool is_private;
        bool is_fork;
        bool is_archived;
        bool is_mirror;
        bool is_forkable;
        int forks_count;
        int stargazers_count;
        int watchers_count;
        int open_issues_count;
        int open_pr_counter;
        int release_counter;
        std::string created_at;
        std::string updated_at;
        std::string pushed_at;
        std::string language;
        std::string website;
        nlohmann::json permissions;
        bool has_issues;
        bool has_wiki;
        bool has_projects;
        bool ignore_whitespace_conflicts;
        bool allow_merge_commits;
        bool allow_rebase;
        bool allow_rebase_explicit;
        bool allow_squash_merge;
        bool avatar_url;
        bool internal;
        std::string mirror_interval;
    };

    struct CodebergIssue {
        int number;
        std::string title;
        std::string body;
        std::string state; // "open", "closed"
        CodebergUser user;
        std::vector<CodebergUser> assignees;
        std::vector<std::string> labels;
        CodebergUser closed_by;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string html_url;
        CodebergRepository repository;
        bool is_pull_request;
        int comments_count;
        std::string deadline;
        std::string ref;
    };

    struct CodebergPullRequest {
        int number;
        std::string title;
        std::string body;
        std::string state; // "open", "closed", "merged"
        std::string head_branch;
        std::string base_branch;
        CodebergUser user;
        CodebergUser merged_by;
        std::vector<CodebergUser> assignees;
        std::vector<std::string> labels;
        std::vector<CodebergUser> requested_reviewers;
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
        bool mergeable;
        bool rebaseable;
        std::string mergeable_state;
        std::string diff_url;
        std::string patch_url;
    };

    struct CodebergRelease {
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
        std::vector<CodebergUser> authors;
        std::vector<std::string> assets;
    };

    struct CodebergTeam {
        int64_t id;
        std::string name;
        std::string description;
        std::string organization;
        std::string permission; // "read", "write", "admin"
        std::vector<CodebergUser> members;
        int members_count;
        int repos_count;
        std::string created_at;
        std::string updated_at;
        bool includes_all_repositories;
    };

    struct CodebergWebhook {
        int64_t id;
        std::string name;
        std::vector<std::string> events;
        std::string url;
        bool is_active;
        std::string created_at;
        std::string updated_at;
        std::string type; // "gitea", "slack", "discord", etc.
        std::string config;
    };

    struct CodebergMilestone {
        int64_t id;
        std::string title;
        std::string description;
        std::string state; // "open", "closed"
        int open_issues;
        int closed_issues;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string due_date;
    };

    struct CodebergFile {
        std::string name;
        std::string path;
        std::string sha;
        int64_t size;
        std::string url;
        std::string html_url;
        std::string git_url;
        std::string download_url;
        std::string type; // "file", "dir", "symlink", "submodule"
        std::string encoding; // "base64" for files
        std::string content;
        std::string target;
    };

    struct CodebergCommit {
        std::string sha;
        std::string html_url;
        CodebergUser author;
        CodebergUser committer;
        std::string message;
        std::vector<std::string> parents;
        std::string created_at;
        int stats_additions;
        int stats_deletions;
        int stats_total;
    };

    struct CodebergBranch {
        std::string name;
        CodebergCommit commit;
        bool is_protected;
        std::string protection_url;
    };

    struct CodebergTag {
        std::string name;
        std::string message;
        std::string id;
        CodebergCommit commit;
        std::string zipball_url;
        std::string tarball_url;
    };

    struct CodebergReview {
        int64_t id;
        CodebergUser user;
        std::string body;
        std::string state; // "APPROVED", "REQUEST_CHANGES", "COMMENT", "PENDING"
        std::string submitted_at;
        std::string commit_id;
    };

    struct CodebergComment {
        int64_t id;
        CodebergUser user;
        std::string body;
        std::string created_at;
        std::string updated_at;
        std::string html_url;
        std::string issue_url;
        std::string pull_request_url;
    };

    struct CodebergReviewRequest {
        CodebergUser user;
        CodebergTeam team;
    };

    // Authentication & Configuration
    struct CodebergConfig {
        std::string base_url = "https://codeberg.org/api/v1";
        std::string token;
        std::string username;
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
    };


    CodebergExtension(const CodebergConfig& config);
    virtual ~CodebergExtension();

    void set_config(const CodebergConfig& config);
    CodebergConfig get_config() const;

    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    CodebergUser get_current_user();
    CodebergUser get_user(const std::string& username);
    std::vector<CodebergUser> list_followers(const std::string& username = "");
    std::vector<CodebergUser> list_following(const std::string& username = "");
    std::vector<CodebergUser> search_users(const std::string& query, int page = 1, int limit = 30);
    CodebergUser update_user(const std::string& full_name, const std::string& website, const std::string& location, const std::string& bio);

    CodebergRepository create_repository(const std::string& name, const std::string& description = "", 
                                       bool is_private = true, bool is_template = false,
                                       bool auto_init = true, const std::string& gitignores = "",
                                       const std::string& license = "", const std::string& readme = "default");
    CodebergRepository get_repository(const std::string& owner, const std::string& repo);
    std::vector<CodebergRepository> list_user_repositories(const std::string& username = "");
    std::vector<CodebergRepository> list_organization_repositories(const std::string& org);
    bool delete_repository(const std::string& owner, const std::string& repo);
    CodebergRepository fork_repository(const std::string& owner, const std::string& repo);
    CodebergRepository migrate_repository(const std::string& clone_addr, const std::string& repo_name,
                                        const std::string& description = "", bool is_private = true);
    
    // Repository Operations with Codeberg enhancements
    void clone_codeberg_repository(const std::string& owner, const std::string& repo, 
                                 const std::string& local_path,
                                 const std::function<bool(size_t, size_t)>& progress_callback = {});
    void sync_fork(const std::string& upstream_owner, const std::string& upstream_repo);

    // Branch Management
    std::vector<CodebergBranch> list_branches(const std::string& owner, const std::string& repo);
    CodebergBranch get_branch(const std::string& owner, const std::string& repo, const std::string& branch);
    CodebergBranch create_branch(const std::string& owner, const std::string& repo,
                               const std::string& branch_name, const std::string& from_branch);
    bool delete_branch(const std::string& owner, const std::string& repo, const std::string& branch);

    // Branch Protection
    struct BranchProtectionRule {
        std::string branch_name;
        bool enable_push;
        bool enable_merge_whitelist;
        bool enable_status_check;
        std::vector<std::string> allowed_merge_users;
        std::vector<std::string> allowed_merge_teams;
        std::vector<std::string> allowed_push_users;
        std::vector<std::string> allowed_push_teams;
        std::vector<std::string> status_check_contexts;
        bool require_signed_commits;
        bool required_approvals;
        bool dismiss_stale_approvals;
        bool require_code_owner_reviews;
        bool block_on_rejected_reviews;
        bool block_on_official_review_requests;
    };

    BranchProtectionRule get_branch_protection(const std::string& owner, const std::string& repo, 
                                              const std::string& branch);
    void set_branch_protection(const std::string& owner, const std::string& repo, 
                              const std::string& branch, const BranchProtectionRule& rule);
    void delete_branch_protection(const std::string& owner, const std::string& repo, 
                                 const std::string& branch);

    // Issues Management
    CodebergIssue create_issue(const std::string& owner, const std::string& repo, 
                             const std::string& title, const std::string& body = "",
                             const std::vector<std::string>& assignees = {},
                             const std::vector<std::string>& labels = {},
                             const std::string& milestone = "", const std::string& deadline = "");
    CodebergIssue get_issue(const std::string& owner, const std::string& repo, int issue_number);
    std::vector<CodebergIssue> list_issues(const std::string& owner, const std::string& repo,
                                          const std::string& state = "open", 
                                          const std::string& assignee = "",
                                          const std::vector<std::string>& labels = {},
                                          const std::string& milestone = "",
                                          const std::string& since = "");
    CodebergIssue update_issue(const std::string& owner, const std::string& repo, int issue_number,
                             const std::string& title = "", const std::string& body = "",
                             const std::string& state = "", 
                             const std::vector<std::string>& assignees = {},
                             const std::vector<std::string>& labels = {},
                             const std::string& milestone = "", const std::string& deadline = "");
    bool close_issue(const std::string& owner, const std::string& repo, int issue_number);
    bool lock_issue(const std::string& owner, const std::string& repo, int issue_number);
    bool unlock_issue(const std::string& owner, const std::string& repo, int issue_number);

    // Issue Comments
    CodebergComment create_issue_comment(const std::string& owner, const std::string& repo,
                                       int issue_number, const std::string& body);
    std::vector<CodebergComment> list_issue_comments(const std::string& owner, const std::string& repo,
                                                   int issue_number);
    CodebergComment update_issue_comment(const std::string& owner, const std::string& repo,
                                       int64_t comment_id, const std::string& body);
    bool delete_issue_comment(const std::string& owner, const std::string& repo, int64_t comment_id);

    // Pull Request Management
    CodebergPullRequest create_pull_request(const std::string& owner, const std::string& repo,
                                          const std::string& title, const std::string& head_branch,
                                          const std::string& base_branch, const std::string& body = "",
                                          bool is_draft = false, const std::vector<std::string>& assignees = {},
                                          const std::vector<std::string>& labels = {},
                                          const std::string& milestone = "");
    CodebergPullRequest get_pull_request(const std::string& owner, const std::string& repo, int pr_number);
    std::vector<CodebergPullRequest> list_pull_requests(const std::string& owner, const std::string& repo,
                                                       const std::string& state = "open",
                                                       const std::string& head_branch = "",
                                                       const std::string& base_branch = "",
                                                       const std::string& sort = "recentupdate",
                                                       const std::string& since = "");
    CodebergPullRequest update_pull_request(const std::string& owner, const std::string& repo, int pr_number,
                                          const std::string& title = "", const std::string& body = "",
                                          const std::string& state = "", const std::string& base_branch = "",
                                          const std::vector<std::string>& assignees = {},
                                          const std::vector<std::string>& labels = {},
                                          const std::string& milestone = "");
    bool merge_pull_request(const std::string& owner, const std::string& repo, int pr_number,
                          const std::string& commit_title = "", const std::string& commit_message = "",
                          const std::string& merge_method = "merge", bool delete_branch_after_merge = false);
    CodebergPullRequest check_pull_request_mergeable(const std::string& owner, const std::string& repo, int pr_number);

    // Code Review Management
    CodebergReview create_review(const std::string& owner, const std::string& repo, int pr_number,
                               const std::string& body, const std::string& event,
                               const std::vector<std::string>& comments = {});
    std::vector<CodebergReview> list_reviews(const std::string& owner, const std::string& repo, int pr_number);
    CodebergReview get_review(const std::string& owner, const std::string& repo, int pr_number, int64_t review_id);
    void delete_review(const std::string& owner, const std::string& repo, int pr_number, int64_t review_id);
    void dismiss_review(const std::string& owner, const std::string& repo, int pr_number, 
                       int64_t review_id, const std::string& message);
    std::vector<CodebergReviewRequest> list_review_requests(const std::string& owner, const std::string& repo, int pr_number);
    void create_review_requests(const std::string& owner, const std::string& repo, int pr_number,
                              const std::vector<std::string>& reviewers,
                              const std::vector<std::string>& team_reviewers);
    void delete_review_requests(const std::string& owner, const std::string& repo, int pr_number,
                              const std::vector<std::string>& reviewers,
                              const std::vector<std::string>& team_reviewers);

    // Releases Management
    CodebergRelease create_release(const std::string& owner, const std::string& repo,
                                 const std::string& tag_name, const std::string& name = "",
                                 const std::string& body = "", bool is_draft = false,
                                 bool is_prerelease = false, const std::string& target_commitish = "");
    std::vector<CodebergRelease> list_releases(const std::string& owner, const std::string& repo);
    CodebergRelease get_release(const std::string& owner, const std::string& repo, int64_t release_id);
    CodebergRelease get_release_by_tag(const std::string& owner, const std::string& repo, 
                                     const std::string& tag_name);
    CodebergRelease update_release(const std::string& owner, const std::string& repo, int64_t release_id,
                                 const std::string& tag_name, const std::string& name,
                                 const std::string& body, bool is_draft, bool is_prerelease,
                                 const std::string& target_commitish);
    bool delete_release(const std::string& owner, const std::string& repo, int64_t release_id);

    // Tags Management
    std::vector<CodebergTag> list_tags(const std::string& owner, const std::string& repo);
    CodebergTag get_tag(const std::string& owner, const std::string& repo, const std::string& tag_name);
    CodebergTag create_tag(const std::string& owner, const std::string& repo,
                          const std::string& tag_name, const std::string& message,
                          const std::string& target_commitish);
    bool delete_tag(const std::string& owner, const std::string& repo, const std::string& tag_name);

    // File Operations
    CodebergFile get_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                         const std::string& ref = "");
    std::vector<CodebergFile> list_files(const std::string& owner, const std::string& repo,
                                       const std::string& path = "", const std::string& ref = "");
    CodebergFile create_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                           const std::string& content, const std::string& message,
                           const std::string& branch = "", const std::string& author_name = "",
                           const std::string& author_email = "");
    CodebergFile update_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                           const std::string& content, const std::string& message,
                           const std::string& sha, const std::string& branch = "",
                           const std::string& author_name = "", const std::string& author_email = "");
    bool delete_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                   const std::string& message, const std::string& sha, const std::string& branch = "",
                   const std::string& author_name = "", const std::string& author_email = "");

    // Commits Management
    CodebergCommit get_commit(const std::string& owner, const std::string& repo, const std::string& sha);
    std::vector<CodebergCommit> list_commits(const std::string& owner, const std::string& repo,
                                           const std::string& sha = "", const std::string& path = "",
                                           const std::string& since = "", const std::string& until = "",
                                           int page = 1, int limit = 30);
    CodebergCommit create_commit(const std::string& owner, const std::string& repo,
                               const std::string& message, const std::string& tree_sha,
                               const std::vector<std::string>& parent_shas,
                               const CodebergUser& author, const CodebergUser& committer);

    // Milestones Management
    CodebergMilestone create_milestone(const std::string& owner, const std::string& repo,
                                     const std::string& title, const std::string& description = "",
                                     const std::string& due_date = "", const std::string& state = "open");
    std::vector<CodebergMilestone> list_milestones(const std::string& owner, const std::string& repo,
                                                 const std::string& state = "");
    CodebergMilestone get_milestone(const std::string& owner, const std::string& repo, int64_t milestone_id);
    CodebergMilestone update_milestone(const std::string& owner, const std::string& repo, int64_t milestone_id,
                                     const std::string& title, const std::string& description = "",
                                     const std::string& due_date = "", const std::string& state = "");
    bool delete_milestone(const std::string& owner, const std::string& repo, int64_t milestone_id);

    // Labels Management
    struct CodebergLabel {
        int64_t id;
        std::string name;
        std::string color;
        std::string description;
        std::string url;
    };

    CodebergLabel create_label(const std::string& owner, const std::string& repo,
                             const std::string& name, const std::string& color,
                             const std::string& description = "");
    std::vector<CodebergLabel> list_labels(const std::string& owner, const std::string& repo);
    CodebergLabel get_label(const std::string& owner, const std::string& repo, int64_t label_id);
    CodebergLabel update_label(const std::string& owner, const std::string& repo, int64_t label_id,
                             const std::string& name, const std::string& color,
                             const std::string& description = "");
    bool delete_label(const std::string& owner, const std::string& repo, int64_t label_id);

    // Teams & Organizations
    std::vector<CodebergTeam> list_teams(const std::string& org);
    CodebergTeam get_team(const std::string& org, int64_t team_id);
    CodebergTeam create_team(const std::string& org, const std::string& name,
                           const std::string& description = "", const std::string& permission = "read",
                           bool includes_all_repositories = false);
    CodebergTeam update_team(const std::string& org, int64_t team_id, const std::string& name,
                           const std::string& description = "", const std::string& permission = "read",
                           bool includes_all_repositories = false);
    bool delete_team(const std::string& org, int64_t team_id);
    std::vector<CodebergUser> list_team_members(const std::string& org, int64_t team_id);
    void add_team_member(const std::string& org, int64_t team_id, const std::string& username);
    void remove_team_member(const std::string& org, int64_t team_id, const std::string& username);
    std::vector<CodebergRepository> list_team_repositories(const std::string& org, int64_t team_id);
    void add_team_repository(const std::string& org, int64_t team_id, const std::string& owner, const std::string& repo);
    void remove_team_repository(const std::string& org, int64_t team_id, const std::string& owner, const std::string& repo);

    // Collaborators Management
    std::vector<CodebergUser> list_collaborators(const std::string& owner, const std::string& repo);
    void add_collaborator(const std::string& owner, const std::string& repo,
                         const std::string& username, const std::string& permission = "write");
    void remove_collaborator(const std::string& owner, const std::string& repo,
                           const std::string& username);
    std::string get_collaborator_permission(const std::string& owner, const std::string& repo,
                                          const std::string& username);

    // Webhooks Management
    CodebergWebhook create_webhook(const std::string& owner, const std::string& repo,
                                 const std::string& url, const std::vector<std::string>& events,
                                 const std::string& secret = "", const std::string& type = "gitea");
    std::vector<CodebergWebhook> list_webhooks(const std::string& owner, const std::string& repo);
    CodebergWebhook get_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);
    CodebergWebhook update_webhook(const std::string& owner, const std::string& repo, int64_t hook_id,
                                 const std::string& url, const std::vector<std::string>& events,
                                 const std::string& secret = "", const std::string& type = "gitea");
    bool delete_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);
    std::string test_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);

    // Notifications
    struct CodebergNotification {
        int64_t id;
        std::string subject_type; // "Issue", "PullRequest", "Commit", "Repository"
        std::string subject_title;
        std::string subject_url;
        std::string repository_full_name;
        bool is_unread;
        bool is_pinned;
        std::string updated_at;
        std::string last_read_at;
    };

    std::vector<CodebergNotification> list_notifications(const std::string& since = "",
                                                       bool all = false,
                                                       const std::vector<std::string>& statuses = {},
                                                       const std::vector<std::string>& subject_types = {});
    void mark_notifications_read(const std::string& last_read_at = "");
    void mark_thread_read(const std::string& owner, const std::string& repo, int64_t thread_id);

    // Search
    struct SearchResult {
        int total_count;
        bool incomplete_results;
        nlohmann::json items;
    };

    SearchResult search_repositories(const std::string& query, int page = 1, int limit = 30,
                                   const std::string& uid = "", const std::string& priority_owner_id = "",
                                   const std::string& topic = "", const std::string& language = "");
    SearchResult search_issues(const std::string& query, int page = 1, int limit = 30,
                             const std::string& state = "");
    SearchResult search_users(const std::string& query, int page = 1, int limit = 30);

    // Administration (for organization owners/admins)
    struct CodebergOrganization {
        int64_t id;
        std::string name;
        std::string full_name;
        std::string email;
        std::string avatar_url;
        std::string description;
        std::string website;
        std::string location;
        bool is_verified;
        int64_t repo_admin_change_team_access;
        std::string created_at;
        std::string updated_at;
    };

    CodebergOrganization get_organization(const std::string& org);
    CodebergOrganization update_organization(const std::string& org, const std::string& full_name,
                                           const std::string& email, const std::string& website,
                                           const std::string& location, const std::string& description);
    std::vector<CodebergUser> list_organization_members(const std::string& org);
    void remove_organization_member(const std::string& org, const std::string& username);

    // Repository Statistics
    struct CodebergStats {
        int total_commits;
        int total_additions;
        int total_deletions;
        std::map<std::string, int> commit_activity;
        std::map<std::string, int> code_frequency;
        std::vector<std::string> contributors;
        std::map<std::string, int> punch_card;
    };

    CodebergStats get_repository_stats(const std::string& owner, const std::string& repo);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    CodebergConfig config_;
    std::mutex api_mutex_;
    std::map<std::string, nlohmann::json> cache_;
    
    // HTTP client implementation
    std::string make_request(const std::string& method, const std::string& url, 
                           const std::string& data = "");
    void handle_http_error(int status_code, const std::string& response);
    void update_rate_limits(const std::string& response_headers);
    
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
    
    // Helper methods for data conversion
    CodebergUser user_from_json(const nlohmann::json& json);
    CodebergRepository repository_from_json(const nlohmann::json& json);
    CodebergIssue issue_from_json(const nlohmann::json& json);
    CodebergPullRequest pull_request_from_json(const nlohmann::json& json);
    CodebergRelease release_from_json(const nlohmann::json& json);
    CodebergTeam team_from_json(const nlohmann::json& json);
    CodebergWebhook webhook_from_json(const nlohmann::json& json);
    CodebergMilestone milestone_from_json(const nlohmann::json& json);
    CodebergFile file_from_json(const nlohmann::json& json);
    CodebergCommit commit_from_json(const nlohmann::json& json);
    CodebergBranch branch_from_json(const nlohmann::json& json);
    CodebergTag tag_from_json(const nlohmann::json& json);
    CodebergReview review_from_json(const nlohmann::json& json);
    CodebergComment comment_from_json(const nlohmann::json& json);
    CodebergLabel label_from_json(const nlohmann::json& json);
    CodebergNotification notification_from_json(const nlohmann::json& json);
    CodebergOrganization organization_from_json(const nlohmann::json& json);
};

#endif // CODEBERG_EXTENSION_H