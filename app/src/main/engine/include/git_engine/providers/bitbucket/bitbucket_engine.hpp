#ifndef BITBUCKET_EXTENSION_H
#define BITBUCKET_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class BitbucketExtension : public GitBase {
public:
    // Bitbucket-specific data structures
    struct BitbucketUser {
        std::string uuid;
        std::string username;
        std::string display_name;
        std::string nickname;
        std::string account_id;
        std::string account_status;
        std::string created_on;
        std::string updated_on;
        bool is_staff;
        std::map<std::string, std::string> links;
        std::string type; // "user"
        std::string website;
        std::string location;
    };

    struct BitbucketTeam {
        std::string uuid;
        std::string username;
        std::string display_name;
        std::string created_on;
        std::string updated_on;
        std::string type; // "team"
        std::map<std::string, std::string> links;
        std::string website;
        std::string location;
    };

    struct BitbucketRepository {
        std::string uuid;
        std::string name;
        std::string full_name;
        std::string slug;
        std::string description;
        std::string scm; // "git"
        std::string website;
        std::string created_on;
        std::string updated_on;
        int size;
        std::string language;
        bool has_issues;
        bool has_wiki;
        bool is_private;
        std::string fork_policy; // "allow_forks", "no_public_forks", "no_forks"
        BitbucketUser owner;
        BitbucketTeam team;
        std::string mainbranch_name;
        std::map<std::string, std::string> links;
        std::vector<std::string> topics;
        std::map<std::string, std::string> project;
    };

    struct BitbucketPullRequest {
        int64_t id;
        std::string title;
        std::string description;
        std::string state; // "OPEN", "MERGED", "DECLINED"
        BitbucketUser author;
        std::vector<BitbucketUser> reviewers;
        std::vector<BitbucketUser> participants;
        BitbucketRepository source_repository;
        BitbucketRepository destination_repository;
        BitbucketBranch source_branch;
        BitbucketBranch destination_branch;
        std::string created_on;
        std::string updated_on;
        std::string closed_on;
        std::string merge_commit;
        int comment_count;
        int task_count;
        bool close_source_branch;
        std::map<std::string, std::string> links;
    };

    struct BitbucketIssue {
        int64_t id;
        std::string title;
        std::string content;
        std::string state; // "new", "open", "resolved", "on hold", "invalid", "duplicate", "wontfix", "closed"
        std::string priority; // "trivial", "minor", "major", "critical", "blocker"
        std::string kind; // "bug", "enhancement", "proposal", "task"
        BitbucketUser reporter;
        BitbucketUser assignee;
        BitbucketRepository repository;
        std::string created_on;
        std::string updated_on;
        std::string edited_on;
        std::vector<std::string> components;
        std::string milestone;
        std::string version;
        int votes;
        int watches;
    };

    struct BitbucketCommit {
        std::string hash;
        std::string message;
        BitbucketUser author;
        BitbucketUser committer;
        std::string date;
        std::vector<std::string> parents;
        std::map<std::string, std::string> links;
    };

    struct BitbucketBranch {
        std::string name;
        BitbucketCommit target;
        std::map<std::string, std::string> links;
    };

    struct BitbucketTag {
        std::string name;
        BitbucketCommit target;
        std::map<std::string, std::string> links;
    };

    struct BitbucketPipeline {
        std::string uuid;
        std::string build_number;
        std::string state; // "PENDING", "IN_PROGRESS", "SUCCESSFUL", "FAILED", "STOPPED", "EXPIRED"
        std::string created_on;
        std::string completed_on;
        std::string trigger; // "PUSH", "MANUAL", "SCHEDULED"
        BitbucketCommit commit;
        std::map<std::string, std::string> target;
        std::vector<std::string> steps;
        std::map<std::string, std::string> links;
    };

    struct BitbucketDeployment {
        std::string uuid;
        std::string name;
        std::string state; // "PENDING", "IN_PROGRESS", "SUCCESSFUL", "FAILED", "STOPPED"
        std::string environment_type; // "Test", "Staging", "Production"
        std::string created_on;
        std::string updated_on;
        BitbucketCommit commit;
        BitbucketPipeline pipeline;
        std::map<std::string, std::string> release;
        std::map<std::string, std::string> links;
    };

    struct BitbucketWebhook {
        std::string uuid;
        std::string description;
        std::string url;
        std::vector<std::string> events;
        bool active;
        std::string created_at;
        std::string updated_at;
        std::map<std::string, std::string> links;
    };

    struct BitbucketSnippet {
        std::string id;
        std::string title;
        std::string description;
        std::string created_on;
        std::string updated_on;
        std::string type; // "snippet"
        bool is_private;
        BitbucketUser creator;
        std::map<std::string, std::string> files;
        std::map<std::string, std::string> links;
    };

    struct BitbucketComment {
        int64_t id;
        std::string content;
        BitbucketUser user;
        std::string created_on;
        std::string updated_on;
        std::map<std::string, std::string> links;
        std::vector<BitbucketComment> replies;
        bool deleted;
        std::string parent_id;
        std::string inline_position;
    };

    struct BitbucketCommitStatus {
        std::string uuid;
        std::string key;
        std::string name;
        std::string description;
        std::string state; // "SUCCESSFUL", "FAILED", "INPROGRESS", "STOPPED"
        std::string url;
        std::string created_on;
        std::string updated_on;
        BitbucketCommit commit;
        std::map<std::string, std::string> links;
    };

    struct BitbucketDiffStat {
        std::string status; // "added", "removed", "modified", "renamed"
        std::string old_path;
        std::string new_path;
        int lines_added;
        int lines_removed;
        std::string type; // "commit_directory", "commit_file"
    };

    struct BitbucketProject {
        std::string uuid;
        std::string key;
        std::string name;
        std::string description;
        bool is_private;
        std::string created_on;
        std::string updated_on;
        BitbucketUser owner;
        std::map<std::string, std::string> links;
    };

    struct BitbucketEnvironment {
        std::string uuid;
        std::string name;
        std::string environment_type; // "Development", "Staging", "Production"
        int rank;
        bool hidden;
        std::map<std::string, std::string> restrictions;
        std::map<std::string, std::string> links;
    };

    struct BitbucketVariable {
        std::string uuid;
        std::string key;
        std::string value;
        bool secured;
        std::string created_on;
        std::string updated_on;
    };

    struct BitbucketBranchRestriction {
        std::string uuid;
        std::string kind; // "require_tasks_to_be_completed", "require_passing_builds", "force", "require_all_dependencies_merged", "push", "require_approvals_to_merge", "restrict_merges", "reset_pullrequest_approvals_on_change", "require_default_reviewer_approvals", "delete"
        std::vector<std::string> users;
        std::vector<std::string> groups;
        std::vector<std::string> value;
        std::map<std::string, std::string> links;
    };

    struct BitbucketDefaultReviewer {
        std::string uuid;
        BitbucketUser user;
        std::string created_on;
        std::map<std::string, std::string> links;
    };

    struct BitbucketDownload {
        std::string uuid;
        std::string name;
        std::string description;
        int size;
        int downloads;
        std::string created_on;
        std::map<std::string, std::string> links;
    };

    // Authentication & Configuration
    struct BitbucketConfig {
        std::string base_url = "https://api.bitbucket.org/2.0";
        std::string username;
        std::string app_password;
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
        std::string workspace; // Required for many operations
    };

    // Constructor & Configuration
    BitbucketExtension(const BitbucketConfig& config);
    virtual ~BitbucketExtension();

    void set_config(const BitbucketConfig& config);
    BitbucketConfig get_config() const;

    // Authentication & Rate Limiting
    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    // User Management
    BitbucketUser get_current_user();
    BitbucketUser get_user(const std::string& username);
    std::vector<BitbucketUser> list_followers(const std::string& username = "");
    std::vector<BitbucketUser> list_following(const std::string& username = "");
    BitbucketUser update_user(const std::string& display_name = "", const std::string& website = "", const std::string& location = "");

    // Workspace Management
    struct BitbucketWorkspace {
        std::string uuid;
        std::string slug;
        std::string name;
        bool is_private;
        std::string created_on;
        std::string updated_on;
        BitbucketUser owner;
        std::map<std::string, std::string> links;
    };

    BitbucketWorkspace get_workspace(const std::string& workspace_slug);
    std::vector<BitbucketWorkspace> list_workspaces();
    std::vector<BitbucketUser> list_workspace_members(const std::string& workspace_slug);
    std::vector<BitbucketProject> list_workspace_projects(const std::string& workspace_slug);

    // Repository Management
    BitbucketRepository create_repository(const std::string& workspace, const std::string& name,
                                        const std::string& description = "", bool is_private = true,
                                        const std::string& fork_policy = "allow_forks",
                                        const std::string& language = "", const std::string& project_key = "");
    BitbucketRepository get_repository(const std::string& workspace, const std::string& repo_slug);
    std::vector<BitbucketRepository> list_repositories(const std::string& workspace = "");
    std::vector<BitbucketRepository> list_user_repositories(const std::string& username = "");
    BitbucketRepository update_repository(const std::string& workspace, const std::string& repo_slug,
                                        const std::string& name = "", const std::string& description = "",
                                        const std::string& fork_policy = "", const std::string& language = "",
                                        const std::string& project_key = "");
    bool delete_repository(const std::string& workspace, const std::string& repo_slug);
    BitbucketRepository fork_repository(const std::string& workspace, const std::string& repo_slug,
                                      const std::string& new_workspace, const std::string& new_name,
                                      const std::string& description = "", bool is_private = true);
    
    // Repository Operations with Bitbucket enhancements
    void clone_bitbucket_repository(const std::string& workspace, const std::string& repo_slug,
                                  const std::string& local_path,
                                  const std::function<bool(size_t, size_t)>& progress_callback = {});

    // Branch Management
    std::vector<BitbucketBranch> list_branches(const std::string& workspace, const std::string& repo_slug);
    BitbucketBranch get_branch(const std::string& workspace, const std::string& repo_slug, const std::string& branch_name);
    BitbucketBranch create_branch(const std::string& workspace, const std::string& repo_slug,
                                const std::string& branch_name, const std::string& target_hash);
    bool delete_branch(const std::string& workspace, const std::string& repo_slug, const std::string& branch_name);
    BitbucketBranch get_main_branch(const std::string& workspace, const std::string& repo_slug);
    BitbucketBranch set_main_branch(const std::string& workspace, const std::string& repo_slug, const std::string& branch_name);

    // Branch Restrictions
    BitbucketBranchRestriction create_branch_restriction(const std::string& workspace, const std::string& repo_slug,
                                                       const std::string& kind, const std::vector<std::string>& users = {},
                                                       const std::vector<std::string>& groups = {}, const std::vector<std::string>& value = {});
    std::vector<BitbucketBranchRestriction> list_branch_restrictions(const std::string& workspace, const std::string& repo_slug);
    BitbucketBranchRestriction get_branch_restriction(const std::string& workspace, const std::string& repo_slug, const std::string& restriction_id);
    BitbucketBranchRestriction update_branch_restriction(const std::string& workspace, const std::string& repo_slug, const std::string& restriction_id,
                                                       const std::string& kind, const std::vector<std::string>& users = {},
                                                       const std::vector<std::string>& groups = {}, const std::vector<std::string>& value = {});
    bool delete_branch_restriction(const std::string& workspace, const std::string& repo_slug, const std::string& restriction_id);

    // Default Reviewers
    BitbucketDefaultReviewer add_default_reviewer(const std::string& workspace, const std::string& repo_slug, const std::string& reviewer_uuid);
    std::vector<BitbucketDefaultReviewer> list_default_reviewers(const std::string& workspace, const std::string& repo_slug);
    bool remove_default_reviewer(const std::string& workspace, const std::string& repo_slug, const std::string& reviewer_uuid);

    // Commits Management
    BitbucketCommit get_commit(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash);
    std::vector<BitbucketCommit> list_commits(const std::string& workspace, const std::string& repo_slug,
                                            const std::string& branch = "", const std::string& path = "",
                                            const std::string& since = "", const std::string& until = "");
    std::vector<BitbucketDiffStat> get_commit_diffstat(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash);
    std::string get_commit_diff(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash);
    std::vector<BitbucketComment> list_commit_comments(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash);
    BitbucketComment create_commit_comment(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash,
                                         const std::string& content, const std::string& line = "", const std::string& file_path = "");

    // Commit Statuses
    BitbucketCommitStatus create_commit_status(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash,
                                             const std::string& key, const std::string& name, const std::string& description,
                                             const std::string& state, const std::string& url = "");
    std::vector<BitbucketCommitStatus> list_commit_statuses(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash);
    BitbucketCommitStatus get_commit_status(const std::string& workspace, const std::string& repo_slug, const std::string& commit_hash, const std::string& key);

    // Pull Request Management
    BitbucketPullRequest create_pull_request(const std::string& workspace, const std::string& repo_slug,
                                           const std::string& title, const std::string& source_branch,
                                           const std::string& destination_branch, const std::string& description = "",
                                           const std::vector<std::string>& reviewers = {}, bool close_source_branch = false);
    BitbucketPullRequest get_pull_request(const std::string& workspace, const std::string& repo_slug, int pr_id);
    std::vector<BitbucketPullRequest> list_pull_requests(const std::string& workspace, const std::string& repo_slug,
                                                        const std::string& state = "OPEN", const std::string& source_branch = "",
                                                        const std::string& destination_branch = "");
    BitbucketPullRequest update_pull_request(const std::string& workspace, const std::string& repo_slug, int pr_id,
                                           const std::string& title = "", const std::string& description = "",
                                           const std::string& state = "", const std::vector<std::string>& reviewers = {},
                                           bool close_source_branch = false);
    bool decline_pull_request(const std::string& workspace, const std::string& repo_slug, int pr_id);
    bool merge_pull_request(const std::string& workspace, const std::string& repo_slug, int pr_id,
                          const std::string& merge_commit_message = "", const std::string& merge_strategy = "merge_commit");
    std::vector<BitbucketCommit> list_pull_request_commits(const std::string& workspace, const std::string& repo_slug, int pr_id);
    std::vector<BitbucketDiffStat> get_pull_request_diffstat(const std::string& workspace, const std::string& repo_slug, int pr_id);
    std::string get_pull_request_diff(const std::string& workspace, const std::string& repo_slug, int pr_id);

    // Pull Request Comments
    std::vector<BitbucketComment> list_pull_request_comments(const std::string& workspace, const std::string& repo_slug, int pr_id);
    BitbucketComment create_pull_request_comment(const std::string& workspace, const std::string& repo_slug, int pr_id,
                                               const std::string& content, const std::string& parent_id = "",
                                               const std::string& line = "", const std::string& file_path = "");
    BitbucketComment update_pull_request_comment(const std::string& workspace, const std::string& repo_slug, int pr_id,
                                               int comment_id, const std::string& content);
    bool delete_pull_request_comment(const std::string& workspace, const std::string& repo_slug, int pr_id, int comment_id);

    // Issues Management
    BitbucketIssue create_issue(const std::string& workspace, const std::string& repo_slug,
                              const std::string& title, const std::string& content = "",
                              const std::string& priority = "major", const std::string& kind = "bug",
                              const std::string& assignee = "", const std::vector<std::string>& components = {});
    BitbucketIssue get_issue(const std::string& workspace, const std::string& repo_slug, int issue_id);
    std::vector<BitbucketIssue> list_issues(const std::string& workspace, const std::string& repo_slug,
                                          const std::string& state = "", const std::string& priority = "",
                                          const std::string& kind = "", const std::string& assignee = "");
    BitbucketIssue update_issue(const std::string& workspace, const std::string& repo_slug, int issue_id,
                              const std::string& title = "", const std::string& content = "",
                              const std::string& state = "", const std::string& priority = "",
                              const std::string& kind = "", const std::string& assignee = "");
    bool delete_issue(const std::string& workspace, const std::string& repo_slug, int issue_id);
    std::vector<BitbucketComment> list_issue_comments(const std::string& workspace, const std::string& repo_slug, int issue_id);
    BitbucketComment create_issue_comment(const std::string& workspace, const std::string& repo_slug, int issue_id, const std::string& content);

    // Pipelines & CI/CD
    BitbucketPipeline get_pipeline(const std::string& workspace, const std::string& repo_slug, const std::string& pipeline_uuid);
    std::vector<BitbucketPipeline> list_pipelines(const std::string& workspace, const std::string& repo_slug,
                                                const std::string& target = "", const std::string& trigger = "");
    BitbucketPipeline trigger_pipeline(const std::string& workspace, const std::string& repo_slug,
                                     const std::string& target_ref, const std::map<std::string, std::string>& variables = {});
    bool stop_pipeline(const std::string& workspace, const std::string& repo_slug, const std::string& pipeline_uuid);
    std::vector<BitbucketVariable> list_pipeline_variables(const std::string& workspace, const std::string& repo_slug);
    BitbucketVariable create_pipeline_variable(const std::string& workspace, const std::string& repo_slug,
                                             const std::string& key, const std::string& value, bool secured = false);
    bool update_pipeline_variable(const std::string& workspace, const std::string& repo_slug, const std::string& variable_uuid,
                                const std::string& key, const std::string& value, bool secured = false);
    bool delete_pipeline_variable(const std::string& workspace, const std::string& repo_slug, const std::string& variable_uuid);

    // Deployments
    BitbucketDeployment create_deployment(const std::string& workspace, const std::string& repo_slug,
                                        const std::string& environment, const std::string& pipeline_uuid,
                                        const std::string& release = "");
    std::vector<BitbucketDeployment> list_deployments(const std::string& workspace, const std::string& repo_slug,
                                                    const std::string& environment = "");
    BitbucketDeployment get_deployment(const std::string& workspace, const std::string& repo_slug, const std::string& deployment_uuid);
    BitbucketDeployment update_deployment(const std::string& workspace, const std::string& repo_slug, const std::string& deployment_uuid,
                                        const std::string& state, const std::string& environment = "");
    bool delete_deployment(const std::string& workspace, const std::string& repo_slug, const std::string& deployment_uuid);

    // Environments
    BitbucketEnvironment create_environment(const std::string& workspace, const std::string& repo_slug,
                                          const std::string& name, const std::string& environment_type,
                                          int rank = 0, bool hidden = false);
    std::vector<BitbucketEnvironment> list_environments(const std::string& workspace, const std::string& repo_slug);
    BitbucketEnvironment get_environment(const std::string& workspace, const std::string& repo_slug, const std::string& environment_uuid);
    BitbucketEnvironment update_environment(const std::string& workspace, const std::string& repo_slug, const std::string& environment_uuid,
                                          const std::string& name, const std::string& environment_type,
                                          int rank = 0, bool hidden = false);
    bool delete_environment(const std::string& workspace, const std::string& repo_slug, const std::string& environment_uuid);

    // Webhooks Management
    BitbucketWebhook create_webhook(const std::string& workspace, const std::string& repo_slug,
                                  const std::string& url, const std::vector<std::string>& events,
                                  const std::string& description = "");
    std::vector<BitbucketWebhook> list_webhooks(const std::string& workspace, const std::string& repo_slug);
    BitbucketWebhook get_webhook(const std::string& workspace, const std::string& repo_slug, const std::string& webhook_uuid);
    BitbucketWebhook update_webhook(const std::string& workspace, const std::string& repo_slug, const std::string& webhook_uuid,
                                  const std::string& url, const std::vector<std::string>& events,
                                  const std::string& description = "");
    bool delete_webhook(const std::string& workspace, const std::string& repo_slug, const std::string& webhook_uuid);
    bool test_webhook(const std::string& workspace, const std::string& repo_slug, const std::string& webhook_uuid);

    // Downloads (File hosting)
    BitbucketDownload upload_download(const std::string& workspace, const std::string& repo_slug,
                                    const std::string& file_path, const std::string& name,
                                    const std::string& description = "");
    std::vector<BitbucketDownload> list_downloads(const std::string& workspace, const std::string& repo_slug);
    BitbucketDownload get_download(const std::string& workspace, const std::string& repo_slug, const std::string& download_uuid);
    bool delete_download(const std::string& workspace, const std::string& repo_slug, const std::string& download_uuid);

    // Snippets Management
    BitbucketSnippet create_snippet(const std::string& workspace, const std::string& title,
                                  const std::string& description, const std::map<std::string, std::string>& files,
                                  bool is_private = true);
    BitbucketSnippet get_snippet(const std::string& workspace, const std::string& snippet_id);
    std::vector<BitbucketSnippet> list_snippets(const std::string& workspace = "");
    BitbucketSnippet update_snippet(const std::string& workspace, const std::string& snippet_id,
                                  const std::string& title = "", const std::string& description = "",
                                  const std::map<std::string, std::string>& files = {});
    bool delete_snippet(const std::string& workspace, const std::string& snippet_id);
    std::string get_snippet_content(const std::string& workspace, const std::string& snippet_id, const std::string& file_path);

    // Projects Management
    BitbucketProject create_project(const std::string& workspace, const std::string& key,
                                  const std::string& name, const std::string& description = "",
                                  bool is_private = true);
    BitbucketProject get_project(const std::string& workspace, const std::string& project_key);
    std::vector<BitbucketProject> list_projects(const std::string& workspace);
    BitbucketProject update_project(const std::string& workspace, const std::string& project_key,
                                  const std::string& name = "", const std::string& description = "",
                                  bool is_private = true);
    bool delete_project(const std::string& workspace, const std::string& project_key);

    // Search
    struct SearchResult {
        int size;
        int page;
        int pagelen;
        std::vector<nlohmann::json> values;
        std::map<std::string, std::string> links;
    };

    SearchResult search_code(const std::string& query, const std::string& workspace = "");
    SearchResult search_issues(const std::string& query, const std::string& workspace = "");
    SearchResult search_repositories(const std::string& query, const std::string& workspace = "");

    // Teams Management
    BitbucketTeam get_team(const std::string& team_slug);
    std::vector<BitbucketTeam> list_teams(const std::string& role = ""); // member, contributor, admin, owner
    std::vector<BitbucketUser> list_team_members(const std::string& team_slug);
    std::vector<BitbucketRepository> list_team_repositories(const std::string& team_slug);
    std::vector<BitbucketProject> list_team_projects(const std::string& team_slug);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    BitbucketConfig config_;
    std::mutex api_mutex_;
    std::map<std::string, nlohmann::json> cache_;
    
    // HTTP client implementation
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
    

    BitbucketUser user_from_json(const nlohmann::json& json);
    BitbucketTeam team_from_json(const nlohmann::json& json);
    BitbucketRepository repository_from_json(const nlohmann::json& json);
    BitbucketPullRequest pull_request_from_json(const nlohmann::json& json);
    BitbucketIssue issue_from_json(const nlohmann::json& json);
    BitbucketCommit commit_from_json(const nlohmann::json& json);
    BitbucketBranch branch_from_json(const nlohmann::json& json);
    BitbucketTag tag_from_json(const nlohmann::json& json);
    BitbucketPipeline pipeline_from_json(const nlohmann::json& json);
    BitbucketDeployment deployment_from_json(const nlohmann::json& json);
    BitbucketWebhook webhook_from_json(const nlohmann::json& json);
    BitbucketSnippet snippet_from_json(const nlohmann::json& json);
    BitbucketComment comment_from_json(const nlohmann::json& json);
    BitbucketCommitStatus commit_status_from_json(const nlohmann::json& json);
    BitbucketDiffStat diffstat_from_json(const nlohmann::json& json);
    BitbucketProject project_from_json(const nlohmann::json& json);
    BitbucketEnvironment environment_from_json(const nlohmann::json& json);
    BitbucketVariable variable_from_json(const nlohmann::json& json);
    BitbucketBranchRestriction branch_restriction_from_json(const nlohmann::json& json);
    BitbucketDefaultReviewer default_reviewer_from_json(const nlohmann::json& json);
    BitbucketDownload download_from_json(const nlohmann::json& json);
    BitbucketWorkspace workspace_from_json(const nlohmann::json& json);
};

#endif // BITBUCKET_EXTENSION_H