#ifndef GITLAB_EXTENSION_H
#define GITLAB_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class GitLabExtension : public GitBase {
public:
    // GitLab-specific data structures
    struct GitLabUser {
        int64_t id;
        std::string username;
        std::string name;
        std::string email;
        std::string avatar_url;
        std::string web_url;
        std::string created_at;
        std::string bio;
        std::string location;
        std::string skype;
        std::string linkedin;
        std::string twitter;
        std::string website_url;
        std::string organization;
        std::string job_title;
        int followers;
        int following;
        bool is_admin;
        bool can_create_group;
        bool can_create_project;
        std::string state; // "active", "blocked"
        std::string external;
        bool private_profile;
        std::vector<std::string> identities;
    };

    struct GitLabProject {
        int64_t id;
        std::string name;
        std::string name_with_namespace;
        std::string description;
        std::string web_url;
        std::string avatar_url;
        std::string ssh_url_to_repo;
        std::string http_url_to_repo;
        std::string namespace_path;
        std::string default_branch;
        std::string visibility; // "private", "internal", "public"
        std::string path;
        std::string path_with_namespace;
        std::string created_at;
        std::string last_activity_at;
        GitLabUser owner;
        bool archived;
        bool empty_repo;
        bool repository_access_level; // "disabled", "private", "enabled"
        bool merge_requests_access_level;
        bool forks_access_level;
        bool wiki_access_level;
        bool jobs_access_level;
        bool snippets_access_level;
        bool pages_access_level;
        bool emails_disabled;
        bool shared_runners_enabled;
        bool lfs_enabled;
        bool request_access_enabled;
        bool only_allow_merge_if_pipeline_succeeds;
        bool only_allow_merge_if_all_discussions_are_resolved;
        bool printing_merge_request_link_enabled;
        bool merge_method; // "merge", "rebase_merge", "ff"
        bool squash_option; // "never", "always", "default_on", "default_off"
        bool remove_source_branch_after_merge;
        bool autoclose_referenced_issues;
        std::string ci_config_path;
        std::vector<std::string> tag_list;
        std::map<std::string, std::string> statistics;
        std::vector<std::string> topics;
    };

    struct GitLabIssue {
        int64_t id;
        int iid;
        std::string title;
        std::string description;
        std::string state; // "opened", "closed"
        GitLabUser author;
        std::vector<GitLabUser> assignees;
        std::vector<std::string> labels;
        GitLabUser closed_by;
        GitLabProject project;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string due_date;
        std::string web_url;
        bool confidential;
        bool discussion_locked;
        int upvotes;
        int downvotes;
        int user_notes_count;
        std::string milestone;
        bool subscribed;
        int time_stats_total_time_spent;
        int time_stats_human_total_time_spent;
        int time_stats_time_estimate;
        int time_stats_human_time_estimate;
        std::vector<std::string> task_completion_status;
        bool has_tasks;
        std::string severity; // "unknown", "low", "medium", "high", "critical"
    };

    struct GitLabMergeRequest {
        int64_t id;
        int iid;
        std::string title;
        std::string description;
        std::string state; // "opened", "closed", "merged", "locked"
        std::string source_branch;
        std::string target_branch;
        GitLabUser author;
        GitLabUser assignee;
        std::vector<GitLabUser> assignees;
        std::vector<std::string> labels;
        GitLabUser merged_by;
        GitLabProject source_project;
        GitLabProject target_project;
        bool work_in_progress;
        bool draft;
        bool squash;
        std::string merge_status; // "can_be_merged", "cannot_be_merged"
        std::string merge_error;
        bool should_remove_source_branch;
        bool force_remove_source_branch;
        std::string merge_commit_sha;
        std::string squash_commit_sha;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string merged_at;
        std::string web_url;
        int upvotes;
        int downvotes;
        int user_notes_count;
        bool subscribed;
        int changes_count;
        std::string diff_refs_base_sha;
        std::string diff_refs_head_sha;
        std::string diff_refs_start_sha;
        bool merge_when_pipeline_succeeds;
        std::string merge_method; // "merge", "rebase_merge", "ff"
        std::vector<std::string> reviewers;
    };

    struct GitLabPipeline {
        int64_t id;
        int iid;
        std::string sha;
        std::string ref;
        std::string status; // "created", "waiting_for_resource", "preparing", "pending", "running", "success", "failed", "canceled", "skipped", "manual", "scheduled"
        std::string source; // "push", "web", "trigger", "schedule", "api", "external", "pipeline", "chat", "webide", "merge_request_event", "external_pull_request_event", "parent_pipeline", "ondemand_dast_scan", "ondemand_dast_validation"
        std::string created_at;
        std::string updated_at;
        std::string started_at;
        std::string finished_at;
        std::string committed_at;
        int duration;
        int queued_duration;
        std::string web_url;
        GitLabUser user;
        GitLabProject project;
        GitLabMergeRequest merge_request;
        std::vector<std::string> tags;
        std::string coverage;
        std::map<std::string, std::string> detailed_status;
    };

    struct GitLabJob {
        int64_t id;
        std::string status;
        std::string stage;
        std::string name;
        std::string ref;
        std::string tag;
        std::string coverage;
        std::string created_at;
        std::string started_at;
        std::string finished_at;
        std::string erased_at;
        double duration;
        double queued_duration;
        GitLabUser user;
        GitLabCommit commit;
        GitLabPipeline pipeline;
        GitLabProject project;
        std::string web_url;
        std::vector<std::string> artifacts;
        std::string runner;
        std::string artifacts_expire_at;
        std::map<std::string, std::string> metadata;
    };

    struct GitLabCommit {
        std::string id;
        std::string short_id;
        std::string title;
        std::string author_name;
        std::string author_email;
        std::string authored_date;
        std::string committer_name;
        std::string committer_email;
        std::string committed_date;
        std::string created_at;
        std::string message;
        std::vector<std::string> parent_ids;
        std::string web_url;
        std::string last_pipeline;
        std::map<std::string, int> stats;
        std::vector<std::string> status;
    };

    struct GitLabBranch {
        std::string name;
        GitLabCommit commit;
        bool merged;
        bool protected;
        bool developers_can_push;
        bool developers_can_merge;
        bool can_push;
        std::string web_url;
    };

    struct GitLabTag {
        std::string name;
        std::string message;
        GitLabCommit commit;
        std::string release;
        bool protected;
    };

    struct GitLabRelease {
        std::string tag_name;
        std::string name;
        std::string description;
        std::string description_html;
        std::string created_at;
        std::string released_at;
        bool upcoming_release;
        std::string milestones;
        GitLabCommit commit;
        std::string author_name;
        std::string author_email;
        std::vector<std::string> assets;
        std::map<std::string, std::string> links;
    };

    struct GitLabMilestone {
        int64_t id;
        int iid;
        int project_id;
        std::string title;
        std::string description;
        std::string state; // "active", "closed"
        std::string created_at;
        std::string updated_at;
        std::string due_date;
        std::string start_date;
        std::string web_url;
        std::map<std::string, int> issue_stats;
    };

    struct GitLabGroup {
        int64_t id;
        std::string name;
        std::string path;
        std::string description;
        std::string visibility; // "private", "internal", "public"
        bool share_with_group_lock;
        bool require_two_factor_authentication;
        int two_factor_grace_period;
        std::string project_creation_level; // "noone", "maintainer", "developer"
        bool auto_devops_enabled;
        std::string subgroup_creation_level; // "owner", "maintainer"
        bool emails_disabled;
        bool mentions_disabled;
        bool lfs_enabled;
        bool request_access_enabled;
        std::string created_at;
        std::string avatar_url;
        std::string web_url;
        std::string full_name;
        std::string full_path;
        int parent_id;
        int shared_runners_minutes_limit;
        int extra_shared_runners_minutes_limit;
        GitLabUser created_by;
        std::vector<std::string> shared_with_groups;
        std::vector<std::string> custom_attributes;
    };

    struct GitLabMember {
        int64_t id;
        std::string username;
        std::string name;
        std::string state;
        std::string avatar_url;
        std::string web_url;
        int access_level; // 10=Guest, 20=Reporter, 30=Developer, 40=Maintainer, 50=Owner
        std::string expires_at;
        std::string group_saml_identity;
    };

    struct GitLabWebhook {
        int64_t id;
        std::string url;
        std::vector<std::string> events;
        bool enable_ssl_verification;
        std::string created_at;
        bool push_events;
        bool push_events_branch_filter;
        bool issues_events;
        bool confidential_issues_events;
        bool merge_requests_events;
        bool tag_push_events;
        bool note_events;
        bool confidential_note_events;
        bool job_events;
        bool pipeline_events;
        bool wiki_page_events;
        bool deployment_events;
        bool releases_events;
        bool emoji_events;
        std::string token;
    };

    struct GitLabVariable {
        std::string key;
        std::string value;
        bool protected_variable;
        bool masked;
        std::string environment_scope;
        std::string variable_type; // "env_var", "file"
    };

    struct GitLabRunner {
        int64_t id;
        std::string description;
        bool active;
        bool is_shared;
        std::string ip_address;
        std::string name;
        bool online;
        bool paused;
        GitLabProject project;
        std::vector<std::string> tag_list;
        std::string runner_type; // "instance_type", "group_type", "project_type"
        std::string status; // "online", "offline", "not_connected", "stale"
        std::string architecture;
        std::string platform;
        std::string revision;
        std::string version;
        std::vector<std::string> contacted_at;
    };

    struct GitLabDeployment {
        int64_t id;
        int iid;
        std::string ref;
        std::string sha;
        std::string created_at;
        std::string updated_at;
        std::string status; // "created", "running", "success", "failed", "canceled"
        std::string environment;
        std::string deployable;
        GitLabUser user;
        GitLabCommit commit;
        std::map<std::string, std::string> variables;
    };

    struct GitLabEnvironment {
        int64_t id;
        std::string name;
        std::string slug;
        std::string external_url;
        std::string state; // "available", "stopped"
        std::string created_at;
        std::string updated_at;
        GitLabProject project;
        GitLabDeployment last_deployment;
        bool auto_stop_at;
        bool prevent_auto_stop;
        std::map<std::string, std::string> tier; // "production", "staging", "testing", "development", "other"
    };

    struct GitLabPackage {
        int64_t id;
        std::string name;
        std::string version;
        std::string package_type; // "conan", "maven", "npm", "pypi", "composer", "nuget", "helm", "golang", "debian", "rubygems", "generic"
        std::string status; // "default", "hidden", "processing", "error", "pending_destruction"
        GitLabProject project;
        std::string created_at;
        std::vector<std::string> pipelines;
        std::vector<std::string> versions;
        std::map<std::string, std::string> package_files;
    };

    struct GitLabWikiPage {
        std::string slug;
        std::string title;
        std::string format; // "markdown", "asciidoc", "rdoc"
        std::string content;
        std::string encoding; // "base64"
        GitLabUser author;
        std::string created_at;
        std::string updated_at;
    };

    struct GitLabSnippet {
        int64_t id;
        std::string title;
        std::string description;
        std::string visibility; // "private", "internal", "public"
        std::string created_at;
        std::string updated_at;
        GitLabProject project;
        GitLabUser author;
        std::vector<std::string> files;
        std::string web_url;
        std::string raw_url;
        std::string ssh_url_to_repo;
        std::string http_url_to_repo;
    };

    struct GitLabDiscussion {
        int64_t id;
        std::string individual_note;
        std::vector<GitLabNote> notes;
        GitLabProject project;
        GitLabCommit commit;
        GitLabMergeRequest merge_request;
        GitLabIssue issue;
        std::string created_at;
        std::string updated_at;
        bool resolved;
        std::string resolved_by;
        std::string resolved_at;
    };

    struct GitLabNote {
        int64_t id;
        std::string body;
        std::string body_html;
        GitLabUser author;
        std::string created_at;
        std::string updated_at;
        bool system;
        std::string noteable_type; // "Issue", "MergeRequest", "Snippet", "Commit"
        int64_t noteable_id;
        bool resolvable;
        bool resolved;
        GitLabUser resolved_by;
        std::string resolved_at;
        std::vector<std::string> commands_changes;
    };

    // Authentication & Configuration
    struct GitLabConfig {
        std::string base_url = "https://gitlab.com/api/v4";
        std::string token;
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
        std::string sudo; // Impersonate user
    };

    // Constructor & Configuration
    GitLabExtension(const GitLabConfig& config);
    virtual ~GitLabExtension();

    void set_config(const GitLabConfig& config);
    GitLabConfig get_config() const;

    // Authentication & Rate Limiting
    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    // User Management
    GitLabUser get_current_user();
    GitLabUser get_user(int64_t user_id);
    GitLabUser get_user_by_username(const std::string& username);
    std::vector<GitLabUser> list_users(const std::string& search = "", bool active = true, bool blocked = false);
    GitLabUser create_user(const std::string& email, const std::string& username, const std::string& name,
                          const std::string& password, const std::string& projects_limit = "10");
    GitLabUser update_user(int64_t user_id, const std::string& email = "", const std::string& username = "",
                          const std::string& name = "", const std::string& projects_limit = "");
    bool delete_user(int64_t user_id);
    std::vector<GitLabUser> list_user_followers(int64_t user_id);
    std::vector<GitLabUser> list_user_following(int64_t user_id);

    // Project Management
    GitLabProject create_project(const std::string& name, const std::string& description = "",
                               const std::string& visibility = "private", bool initialize_with_readme = true,
                               const std::vector<std::string>& tag_list = {});
    GitLabProject get_project(int64_t project_id);
    GitLabProject get_project_by_path(const std::string& namespace_path, const std::string& project_path);
    std::vector<GitLabProject> list_projects(const std::string& search = "", bool owned = false,
                                           bool starred = false, const std::string& visibility = "",
                                           const std::string& order_by = "created_at",
                                           const std::string& sort = "desc");
    GitLabProject update_project(int64_t project_id, const std::string& name = "", const std::string& description = "",
                               const std::string& default_branch = "", const std::string& visibility = "");
    bool delete_project(int64_t project_id);
    GitLabProject fork_project(int64_t project_id, const std::string& namespace_path = "");
    std::vector<GitLabProject> list_forks(int64_t project_id);
    bool star_project(int64_t project_id);
    bool unstar_project(int64_t project_id);

    // Repository Operations with GitLab enhancements
    void clone_gitlab_project(const std::string& namespace_path, const std::string& project_path,
                            const std::string& local_path,
                            const std::function<bool(size_t, size_t)>& progress_callback = {});

    // Branch Management
    std::vector<GitLabBranch> list_branches(int64_t project_id, const std::string& search = "");
    GitLabBranch get_branch(int64_t project_id, const std::string& branch_name);
    GitLabBranch create_branch(int64_t project_id, const std::string& branch_name, const std::string& ref);
    bool delete_branch(int64_t project_id, const std::string& branch_name);
    bool protect_branch(int64_t project_id, const std::string& branch_name,
                       bool developers_can_push = false, bool developers_can_merge = false);
    bool unprotect_branch(int64_t project_id, const std::string& branch_name);

    // Commits Management
    GitLabCommit get_commit(int64_t project_id, const std::string& sha);
    std::vector<GitLabCommit> list_commits(int64_t project_id, const std::string& ref_name = "",
                                         const std::string& since = "", const std::string& until = "",
                                         const std::string& path = "");
    GitLabCommit create_commit(int64_t project_id, const std::string& branch, const std::string& message,
                             const std::vector<std::string>& actions, const std::string& author_email = "",
                             const std::string& author_name = "");
    std::string get_commit_diff(int64_t project_id, const std::string& sha);
    std::vector<GitLabNote> list_commit_comments(int64_t project_id, const std::string& sha);
    GitLabNote create_commit_comment(int64_t project_id, const std::string& sha, const std::string& note,
                                   const std::string& path = "", int line = 0, int line_type = 0);

    // Issues Management
    GitLabIssue create_issue(int64_t project_id, const std::string& title, const std::string& description = "",
                           const std::vector<std::string>& labels = {}, const std::string& assignee_ids = "",
                           const std::string& milestone_id = "", const std::string& due_date = "");
    GitLabIssue get_issue(int64_t project_id, int issue_iid);
    std::vector<GitLabIssue> list_issues(int64_t project_id, const std::string& state = "opened",
                                       const std::vector<std::string>& labels = {}, const std::string& milestone = "",
                                       const std::string& assignee_username = "");
    GitLabIssue update_issue(int64_t project_id, int issue_iid, const std::string& title = "",
                           const std::string& description = "", const std::string& state_event = "",
                           const std::vector<std::string>& labels = {}, const std::string& assignee_ids = "");
    bool delete_issue(int64_t project_id, int issue_iid);
    std::vector<GitLabNote> list_issue_notes(int64_t project_id, int issue_iid);
    GitLabNote create_issue_note(int64_t project_id, int issue_iid, const std::string& body);
    std::vector<GitLabDiscussion> list_issue_discussions(int64_t project_id, int issue_iid);

    // Merge Requests Management
    GitLabMergeRequest create_merge_request(int64_t project_id, const std::string& source_branch,
                                          const std::string& target_branch, const std::string& title,
                                          const std::string& description = "", const std::vector<std::string>& labels = {},
                                          bool remove_source_branch = false, bool squash = false);
    GitLabMergeRequest get_merge_request(int64_t project_id, int merge_request_iid);
    std::vector<GitLabMergeRequest> list_merge_requests(int64_t project_id, const std::string& state = "opened",
                                                       const std::string& source_branch = "",
                                                       const std::string& target_branch = "");
    GitLabMergeRequest update_merge_request(int64_t project_id, int merge_request_iid, const std::string& title = "",
                                          const std::string& description = "", const std::string& target_branch = "",
                                          const std::vector<std::string>& labels = {}, const std::string& state_event = "");
    bool delete_merge_request(int64_t project_id, int merge_request_iid);
    bool accept_merge_request(int64_t project_id, int merge_request_iid, const std::string& merge_commit_message = "",
                            bool should_remove_source_branch = false, bool squash = false,
                            const std::string& squash_commit_message = "");
    std::vector<GitLabNote> list_merge_request_notes(int64_t project_id, int merge_request_iid);
    GitLabNote create_merge_request_note(int64_t project_id, int merge_request_iid, const std::string& body);
    std::vector<GitLabDiscussion> list_merge_request_discussions(int64_t project_id, int merge_request_iid);
    std::vector<GitLabCommit> list_merge_request_commits(int64_t project_id, int merge_request_iid);
    std::string get_merge_request_changes(int64_t project_id, int merge_request_iid);

    // Pipelines & CI/CD
    GitLabPipeline create_pipeline(int64_t project_id, const std::string& ref, const std::vector<GitLabVariable>& variables = {});
    GitLabPipeline get_pipeline(int64_t project_id, int pipeline_id);
    std::vector<GitLabPipeline> list_pipelines(int64_t project_id, const std::string& ref = "", const std::string& scope = "");
    bool cancel_pipeline(int64_t project_id, int pipeline_id);
    bool retry_pipeline(int64_t project_id, int pipeline_id);
    std::vector<GitLabJob> list_pipeline_jobs(int64_t project_id, int pipeline_id);
    GitLabJob get_job(int64_t project_id, int job_id);
    std::string get_job_log(int64_t project_id, int job_id);
    bool retry_job(int64_t project_id, int job_id);
    bool cancel_job(int64_t project_id, int job_id);
    bool play_job(int64_t project_id, int job_id);
    std::vector<GitLabVariable> list_pipeline_variables(int64_t project_id);
    GitLabVariable create_pipeline_variable(int64_t project_id, const std::string& key, const std::string& value,
                                          bool protected_variable = false, bool masked = false);
    bool update_pipeline_variable(int64_t project_id, const std::string& key, const std::string& value,
                                bool protected_variable = false, bool masked = false);
    bool delete_pipeline_variable(int64_t project_id, const std::string& key);

    // Environments & Deployments
    GitLabEnvironment create_environment(int64_t project_id, const std::string& name, const std::string& external_url = "");
    std::vector<GitLabEnvironment> list_environments(int64_t project_id, const std::string& name = "");
    GitLabEnvironment get_environment(int64_t project_id, int environment_id);
    bool delete_environment(int64_t project_id, int environment_id);
    GitLabDeployment create_deployment(int64_t project_id, const std::string& environment, const std::string& ref,
                                     const std::string& status, const std::map<std::string, std::string>& variables = {});
    std::vector<GitLabDeployment> list_deployments(int64_t project_id, const std::string& environment = "");

    // Releases Management
    GitLabRelease create_release(int64_t project_id, const std::string& tag_name, const std::string& name,
                               const std::string& description, const std::string& ref = "");
    std::vector<GitLabRelease> list_releases(int64_t project_id);
    GitLabRelease get_release(int64_t project_id, const std::string& tag_name);
    GitLabRelease update_release(int64_t project_id, const std::string& tag_name, const std::string& name = "",
                               const std::string& description = "");
    bool delete_release(int64_t project_id, const std::string& tag_name);

    // Groups Management
    GitLabGroup create_group(const std::string& name, const std::string& path, const std::string& description = "",
                           const std::string& visibility = "private", bool lfs_enabled = true,
                           bool request_access_enabled = true);
    GitLabGroup get_group(int64_t group_id);
    GitLabGroup get_group_by_path(const std::string& group_path);
    std::vector<GitLabGroup> list_groups(const std::string& search = "", bool owned = false);
    GitLabGroup update_group(int64_t group_id, const std::string& name = "", const std::string& path = "",
                           const std::string& description = "", const std::string& visibility = "");
    bool delete_group(int64_t group_id);
    std::vector<GitLabProject> list_group_projects(int64_t group_id);
    std::vector<GitLabMember> list_group_members(int64_t group_id);
    GitLabMember add_group_member(int64_t group_id, int user_id, int access_level);
    bool remove_group_member(int64_t group_id, int user_id);

    // Members & Permissions
    std::vector<GitLabMember> list_project_members(int64_t project_id);
    GitLabMember add_project_member(int64_t project_id, int user_id, int access_level,
                                  const std::string& expires_at = "");
    bool remove_project_member(int64_t project_id, int user_id);
    GitLabMember update_project_member(int64_t project_id, int user_id, int access_level,
                                     const std::string& expires_at = "");

    // Webhooks Management
    GitLabWebhook create_webhook(int64_t project_id, const std::string& url,
                               const std::vector<std::string>& events, bool enable_ssl_verification = true,
                               const std::string& token = "");
    std::vector<GitLabWebhook> list_webhooks(int64_t project_id);
    GitLabWebhook get_webhook(int64_t project_id, int hook_id);
    GitLabWebhook update_webhook(int64_t project_id, int hook_id, const std::string& url,
                               const std::vector<std::string>& events, bool enable_ssl_verification = true,
                               const std::string& token = "");
    bool delete_webhook(int64_t project_id, int hook_id);
    bool test_webhook(int64_t project_id, int hook_id);

    // Runners Management
    std::vector<GitLabRunner> list_project_runners(int64_t project_id);
    GitLabRunner enable_runner(int64_t project_id, int runner_id);
    bool disable_runner(int64_t project_id, int runner_id);
    std::vector<GitLabRunner> list_group_runners(int64_t group_id);
    std::vector<GitLabRunner> list_all_runners();
    GitLabRunner get_runner(int runner_id);
    GitLabRunner update_runner(int runner_id, const std::string& description = "", bool active = true,
                             const std::vector<std::string>& tag_list = {}, bool run_untagged = true,
                             bool locked = false);
    bool delete_runner(int runner_id);

    // Packages Management
    GitLabPackage get_package(int64_t project_id, int package_id);
    std::vector<GitLabPackage> list_packages(int64_t project_id, const std::string& package_type = "");
    bool delete_package(int64_t project_id, int package_id);
    std::vector<GitLabPackage> list_group_packages(int64_t group_id, const std::string& package_type = "");

    // Wiki Management
    GitLabWikiPage create_wiki_page(int64_t project_id, const std::string& slug, const std::string& title,
                                  const std::string& content, const std::string& format = "markdown");
    GitLabWikiPage get_wiki_page(int64_t project_id, const std::string& slug);
    std::vector<GitLabWikiPage> list_wiki_pages(int64_t project_id);
    GitLabWikiPage update_wiki_page(int64_t project_id, const std::string& slug, const std::string& title = "",
                                  const std::string& content = "", const std::string& format = "markdown");
    bool delete_wiki_page(int64_t project_id, const std::string& slug);

    // Snippets Management
    GitLabSnippet create_snippet(int64_t project_id, const std::string& title, const std::string& description,
                               const std::vector<std::string>& files, const std::string& visibility = "private");
    GitLabSnippet get_snippet(int64_t project_id, int snippet_id);
    std::vector<GitLabSnippet> list_snippets(int64_t project_id);
    GitLabSnippet update_snippet(int64_t project_id, int snippet_id, const std::string& title = "",
                               const std::string& description = "", const std::vector<std::string>& files = {});
    bool delete_snippet(int64_t project_id, int snippet_id);
    std::string get_snippet_content(int64_t project_id, int snippet_id, const std::string& file_path);

    // Search
    struct SearchResult {
        int total_count;
        std::vector<nlohmann::json> items;
    };

    SearchResult search_projects(const std::string& query, const std::string& scope = "projects");
    SearchResult search_issues(const std::string& query, int64_t project_id = 0);
    SearchResult search_merge_requests(const std::string& query, int64_t project_id = 0);
    SearchResult search_users(const std::string& query);
    SearchResult search_groups(const std::string& query);

    // Labels Management
    struct GitLabLabel {
        int64_t id;
        std::string name;
        std::string color;
        std::string description;
        int open_issues_count;
        int closed_issues_count;
        int open_merge_requests_count;
        bool subscribed;
        int priority;
    };

    GitLabLabel create_label(int64_t project_id, const std::string& name, const std::string& color,
                           const std::string& description = "");
    std::vector<GitLabLabel> list_labels(int64_t project_id);
    GitLabLabel update_label(int64_t project_id, const std::string& name, const std::string& new_name = "",
                           const std::string& color = "", const std::string& description = "");
    bool delete_label(int64_t project_id, const std::string& name);

    // Milestones Management
    GitLabMilestone create_milestone(int64_t project_id, const std::string& title, const std::string& description = "",
                                   const std::string& due_date = "", const std::string& start_date = "");
    std::vector<GitLabMilestone> list_milestones(int64_t project_id, const std::string& state = "");
    GitLabMilestone get_milestone(int64_t project_id, int milestone_id);
    GitLabMilestone update_milestone(int64_t project_id, int milestone_id, const std::string& title = "",
                                   const std::string& description = "", const std::string& due_date = "",
                                   const std::string& start_date = "", const std::string& state_event = "");
    bool delete_milestone(int64_t project_id, int milestone_id);

    // Epics (GitLab Premium/Ultimate)
    struct GitLabEpic {
        int64_t id;
        int iid;
        int group_id;
        std::string title;
        std::string description;
        std::string state; // "opened", "closed"
        bool confidential;
        std::vector<std::string> labels;
        std::string created_at;
        std::string updated_at;
        GitLabUser author;
        std::string start_date;
        std::string due_date;
        std::string web_url;
    };

    GitLabEpic create_epic(int64_t group_id, const std::string& title, const std::string& description = "",
                          const std::vector<std::string>& labels = {}, bool confidential = false);
    std::vector<GitLabEpic> list_epics(int64_t group_id, const std::string& state = "");
    GitLabEpic get_epic(int64_t group_id, int epic_iid);
    GitLabEpic update_epic(int64_t group_id, int epic_iid, const std::string& title = "",
                          const std::string& description = "", const std::vector<std::string>& labels = {});
    bool delete_epic(int64_t group_id, int epic_iid);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    GitLabConfig config_;
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
    GitLabUser user_from_json(const nlohmann::json& json);
    GitLabProject project_from_json(const nlohmann::json& json);
    GitLabIssue issue_from_json(const nlohmann::json& json);
    GitLabMergeRequest merge_request_from_json(const nlohmann::json& json);
    GitLabPipeline pipeline_from_json(const nlohmann::json& json);
    GitLabJob job_from_json(const nlohmann::json& json);
    GitLabCommit commit_from_json(const nlohmann::json& json);
    GitLabBranch branch_from_json(const nlohmann::json& json);
    GitLabTag tag_from_json(const nlohmann::json& json);
    GitLabRelease release_from_json(const nlohmann::json& json);
    GitLabMilestone milestone_from_json(const nlohmann::json& json);
    GitLabGroup group_from_json(const nlohmann::json& json);
    GitLabMember member_from_json(const nlohmann::json& json);
    GitLabWebhook webhook_from_json(const nlohmann::json& json);
    GitLabVariable variable_from_json(const nlohmann::json& json);
    GitLabRunner runner_from_json(const nlohmann::json& json);
    GitLabDeployment deployment_from_json(const nlohmann::json& json);
    GitLabEnvironment environment_from_json(const nlohmann::json& json);
    GitLabPackage package_from_json(const nlohmann::json& json);
    GitLabWikiPage wiki_page_from_json(const nlohmann::json& json);
    GitLabSnippet snippet_from_json(const nlohmann::json& json);
    GitLabDiscussion discussion_from_json(const nlohmann::json& json);
    GitLabNote note_from_json(const nlohmann::json& json);
    GitLabLabel label_from_json(const nlohmann::json& json);
    GitLabEpic epic_from_json(const nlohmann::json& json);
};

#endif // GITLAB_EXTENSION_H