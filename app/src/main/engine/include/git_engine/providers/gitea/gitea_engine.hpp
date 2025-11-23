#ifndef GITEA_EXTENSION_H
#define GITEA_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class GiteaExtension : public GitBase {
public:
    // Gitea-specific data structures
    struct GiteaUser {
        int64_t id;
        std::string login;
        std::string full_name;
        std::string email;
        std::string avatar_url;
        std::string language;
        bool is_admin;
        bool is_restricted;
        bool is_active;
        bool prohibit_login;
        std::string location;
        std::string website;
        std::string description;
        std::string visibility; // "public", "limited", "private"
        std::string created;
        std::string updated;
        std::string last_login;
        int64_t repo_admin_change_team_access;
    };

    struct GiteaRepository {
        int64_t id;
        std::string name;
        std::string full_name;
        std::string description;
        std::string empty;
        std::string private_;
        std::string fork;
        std::string template_;
        std::string parent;
        std::string mirror;
        int64_t size;
        std::string html_url;
        std::string ssh_url;
        std::string clone_url;
        std::string original_url;
        std::string website;
        int stars_count;
        int forks_count;
        int watchers_count;
        int open_issues_count;
        std::string open_pr_counter;
        int release_counter;
        int default_branch;
        bool archived;
        std::string created_at;
        std::string updated_at;
        std::string permissions;
        bool has_issues;
        bool has_projects;
        bool has_wiki;
        bool has_pull_requests;
        bool ignore_whitespace_conflicts;
        bool allow_merge_commits;
        bool allow_rebase;
        bool allow_rebase_explicit;
        bool allow_squash_merge;
        bool allow_rebase_update;
        bool default_delete_branch_after_merge;
        bool default_merge_style;
        std::string avatar_url;
        std::string internal;
        std::string mirror_interval;
        GiteaUser owner;
        GiteaUser internal_tracker;
        GiteaUser external_tracker;
        GiteaUser external_wiki;
    };

    struct GiteaOrganization {
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

    struct GiteaTeam {
        int64_t id;
        std::string name;
        std::string description;
        GiteaOrganization organization;
        std::string permission; // "none", "read", "write", "admin", "owner"
        bool includes_all_repositories;
        std::vector<std::string> units; // "repo.code", "repo.issues", "repo.ext_issues", "repo.wiki", "repo.pulls", "repo.releases", "repo.projects", "repo.ext_wiki"
        std::vector<std::string> units_map;
        bool can_create_org_repo;
        std::string created_at;
        std::string updated_at;
    };

    struct GiteaIssue {
        int64_t id;
        std::string url;
        std::string html_url;
        int number;
        GiteaUser user;
        GiteaUser original_author;
        std::string original_author_id;
        std::string title;
        std::string body;
        std::vector<GiteaUser> assignees;
        GiteaUser assignee;
        std::vector<GiteaLabel> labels;
        GiteaMilestone milestone;
        std::string state; // "open", "closed"
        bool is_locked;
        int comments;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
        std::string due_date;
        GiteaRepository repository;
        GiteaUser closed_by;
        int64_t repo_id;
        std::string repo_owner_id;
        std::string repo_name;
        bool pin_order;
    };

    struct GiteaPullRequest {
        int64_t id;
        std::string url;
        std::string html_url;
        std::string diff_url;
        std::string patch_url;
        int number;
        std::string state; // "open", "closed"
        bool locked;
        std::string title;
        std::string body;
        std::vector<GiteaLabel> labels;
        GiteaMilestone milestone;
        GiteaUser assignee;
        std::vector<GiteaUser> assignees;
        GiteaUser user;
        GiteaRepository head;
        GiteaRepository base;
        GiteaUser merged_by;
        std::string merged_at;
        std::string merge_commit_sha;
        bool mergeable;
        bool rebaseable;
        std::string mergeable_state;
        std::string created_at;
        std::string updated_at;
        std::string closed_at;
    };

    struct GiteaRelease {
        int64_t id;
        GiteaUser author;
        std::string tag_name;
        std::string target_commitish;
        std::string name;
        std::string body;
        std::string url;
        std::string html_url;
        std::string tarball_url;
        std::string zipball_url;
        bool draft;
        bool prerelease;
        std::string created_at;
        std::string published_at;
        std::vector<GiteaAttachment> assets;
    };

    struct GiteaMilestone {
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

    struct GiteaLabel {
        int64_t id;
        std::string name;
        std::string color;
        std::string description;
        std::string url;
    };

    struct GiteaComment {
        int64_t id;
        std::string html_url;
        GiteaUser user;
        GiteaUser original_author;
        std::string original_author_id;
        std::string body;
        std::string created_at;
        std::string updated_at;
    };

    struct GiteaReview {
        int64_t id;
        GiteaUser reviewer;
        GiteaUser review_team;
        std::string state; // "PENDING", "APPROVED", "CHANGES_REQUESTED", "COMMENT", "REQUEST_CHANGE", "REQUEST_REVIEW"
        std::string body;
        std::string commit_id;
        bool stale;
        std::string submitted_at;
    };

    struct GiteaWebhook {
        int64_t id;
        std::string type; // "gitea", "slack", "discord", "dingtalk", "telegram", "msteams", "feishu", "wechatwork", "packagist"
        GiteaRepository repository;
        std::vector<std::string> events;
        bool active;
        GiteaUser author;
        std::string config;
        std::string created_at;
        std::string updated_at;
    };

    struct GiteaPackage {
        int64_t id;
        GiteaUser owner;
        GiteaRepository repository;
        std::string type; // "alpine", "cargo", "chef", "composer", "conan", "conda", "container", "cran", "debian", "generic", "go", "helm", "maven", "npm", "nuget", "pub", "pypi", "rpm", "rubygems", "swift", "vagrant"
        std::string name;
        std::string version;
        std::string version_created;
        std::vector<GiteaPackageFile> files;
    };

    struct GiteaAction {
        int64_t id;
        GiteaUser actor;
        std::string owner_id;
        std::string repo_id;
        std::string ref_name;
        std::string workflow_id;
        std::string run_number;
        std::string event; // "push", "pull_request", "issues", "create", "delete", "fork", "watch", "release", "package", "schedule", "repository_dispatch"
        std::string status; // "waiting", "running", "success", "failure", "cancelled", "skipped"
        std::string created;
        std::string started;
        std::string stopped;
    };

    struct GiteaNotification {
        int64_t id;
        std::string type; // "issue", "pull", "commit", "repository"
        std::string status; // "unread", "read", "pinned"
        std::string url;
        GiteaRepository repository;
        GiteaUser subject;
        std::string unread;
        bool pinned;
        std::string created_at;
        std::string updated_at;
    };

    struct GiteaWikiPage {
        std::string title;
        std::string content;
        std::string html_content;
        std::string last_modified;
        GiteaUser last_commit_user;
        std::string last_commit_hash;
        std::string last_commit_time;
        std::string sub_url;
        std::vector<std::string> editors;
    };

    struct GiteaFileResponse {
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
        std::vector<GiteaFileResponse> entries;
    };

    struct GiteaBranch {
        std::string name;
        GiteaCommit commit;
        bool protected;
        std::string protection_url;
    };

    struct GiteaTag {
        std::string name;
        std::string message;
        std::string id;
        GiteaCommit commit;
        std::string zipball_url;
        std::string tarball_url;
    };

    struct GiteaCommit {
        std::string sha;
        std::string html_url;
        GiteaUser author;
        GiteaUser committer;
        std::string message;
        std::vector<std::string> parents;
        std::string created_at;
        int stats_additions;
        int stats_deletions;
        int stats_total;
        std::vector<GiteaFileResponse> files;
    };

    struct GiteaReviewRequest {
        GiteaUser user;
        GiteaTeam team;
    };

    // Authentication & Configuration
    struct GiteaConfig {
        std::string base_url = "https://gitea.example.com/api/v1";
        std::string token;
        std::string username;
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
    };

    // Constructor & Configuration
    GiteaExtension(const GiteaConfig& config);
    virtual ~GiteaExtension();

    void set_config(const GiteaConfig& config);
    GiteaConfig get_config() const;

    // Authentication & Rate Limiting
    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    // User Management
    GiteaUser get_current_user();
    GiteaUser get_user(const std::string& username);
    std::vector<GiteaUser> list_users(int page = 1, int limit = 30);
    GiteaUser create_user(const std::string& login, const std::string& email, const std::string& full_name = "");
    GiteaUser update_user(const std::string& username, const std::string& full_name = "", const std::string& email = "",
                         const std::string& website = "", const std::string& location = "", const std::string& description = "");
    bool delete_user(const std::string& username);
    std::vector<GiteaUser> list_followers(const std::string& username = "");
    std::vector<GiteaUser> list_following(const std::string& username = "");
    bool follow_user(const std::string& username);
    bool unfollow_user(const std::string& username);

    // Repository Management
    GiteaRepository create_repository(const std::string& name, const std::string& description = "",
                                    bool is_private = true, bool is_template = false, bool auto_init = true,
                                    const std::string& gitignores = "", const std::string& license = "",
                                    const std::string& readme = "default");
    GiteaRepository get_repository(const std::string& owner, const std::string& repo);
    std::vector<GiteaRepository> list_user_repositories(const std::string& username = "");
    std::vector<GiteaRepository> list_organization_repositories(const std::string& org);
    GiteaRepository update_repository(const std::string& owner, const std::string& repo, const std::string& name = "",
                                    const std::string& description = "", const std::string& website = "",
                                    bool has_issues = true, bool has_projects = true, bool has_wiki = true,
                                    bool is_private = true, bool is_template = false, bool allow_squash_merge = true,
                                    bool allow_merge_commits = true, bool allow_rebase = true, bool allow_rebase_explicit = true,
                                    bool default_delete_branch_after_merge = false, bool archived = false);
    bool delete_repository(const std::string& owner, const std::string& repo);
    GiteaRepository fork_repository(const std::string& owner, const std::string& repo, const std::string& organization = "");
    GiteaRepository migrate_repository(const std::string& clone_addr, const std::string& repo_name,
                                     const std::string& description = "", bool is_private = true);
    
    // Repository Operations with Gitea enhancements
    void clone_gitea_repository(const std::string& owner, const std::string& repo, 
                              const std::string& local_path,
                              const std::function<bool(size_t, size_t)>& progress_callback = {});
    void sync_fork(const std::string& upstream_owner, const std::string& upstream_repo);

    // Branch Management
    std::vector<GiteaBranch> list_branches(const std::string& owner, const std::string& repo);
    GiteaBranch get_branch(const std::string& owner, const std::string& repo, const std::string& branch);
    GiteaBranch create_branch(const std::string& owner, const std::string& repo,
                            const std::string& branch_name, const std::string& from_branch);
    bool delete_branch(const std::string& owner, const std::string& repo, const std::string& branch);
    GiteaBranch get_default_branch(const std::string& owner, const std::string& repo);
    GiteaBranch set_default_branch(const std::string& owner, const std::string& repo, const std::string& branch);

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
    GiteaIssue create_issue(const std::string& owner, const std::string& repo, 
                          const std::string& title, const std::string& body = "",
                          const std::vector<std::string>& assignees = {},
                          const std::vector<std::string>& labels = {},
                          const std::string& milestone = "", const std::string& deadline = "");
    GiteaIssue get_issue(const std::string& owner, const std::string& repo, int issue_number);
    std::vector<GiteaIssue> list_issues(const std::string& owner, const std::string& repo,
                                      const std::string& state = "open", 
                                      const std::string& assignee = "",
                                      const std::vector<std::string>& labels = {},
                                      const std::string& milestone = "",
                                      const std::string& since = "");
    GiteaIssue update_issue(const std::string& owner, const std::string& repo, int issue_number,
                          const std::string& title = "", const std::string& body = "",
                          const std::string& state = "", 
                          const std::vector<std::string>& assignees = {},
                          const std::vector<std::string>& labels = {},
                          const std::string& milestone = "", const std::string& deadline = "");
    bool close_issue(const std::string& owner, const std::string& repo, int issue_number);
    bool lock_issue(const std::string& owner, const std::string& repo, int issue_number);
    bool unlock_issue(const std::string& owner, const std::string& repo, int issue_number);

    // Issue Comments
    GiteaComment create_issue_comment(const std::string& owner, const std::string& repo,
                                    int issue_number, const std::string& body);
    std::vector<GiteaComment> list_issue_comments(const std::string& owner, const std::string& repo,
                                                int issue_number);
    GiteaComment update_issue_comment(const std::string& owner, const std::string& repo,
                                    int64_t comment_id, const std::string& body);
    bool delete_issue_comment(const std::string& owner, const std::string& repo, int64_t comment_id);

    // Pull Request Management
    GiteaPullRequest create_pull_request(const std::string& owner, const std::string& repo,
                                       const std::string& title, const std::string& head_branch,
                                       const std::string& base_branch, const std::string& body = "",
                                       bool is_draft = false, const std::vector<std::string>& assignees = {},
                                       const std::vector<std::string>& labels = {},
                                       const std::string& milestone = "");
    GiteaPullRequest get_pull_request(const std::string& owner, const std::string& repo, int pr_number);
    std::vector<GiteaPullRequest> list_pull_requests(const std::string& owner, const std::string& repo,
                                                   const std::string& state = "open",
                                                   const std::string& head_branch = "",
                                                   const std::string& base_branch = "",
                                                   const std::string& sort = "recentupdate",
                                                   const std::string& since = "");
    GiteaPullRequest update_pull_request(const std::string& owner, const std::string& repo, int pr_number,
                                       const std::string& title = "", const std::string& body = "",
                                       const std::string& state = "", const std::string& base_branch = "",
                                       const std::vector<std::string>& assignees = {},
                                       const std::vector<std::string>& labels = {},
                                       const std::string& milestone = "");
    bool merge_pull_request(const std::string& owner, const std::string& repo, int pr_number,
                          const std::string& commit_title = "", const std::string& commit_message = "",
                          const std::string& merge_method = "merge", bool delete_branch_after_merge = false);
    GiteaPullRequest check_pull_request_mergeable(const std::string& owner, const std::string& repo, int pr_number);

    // Code Review Management
    GiteaReview create_review(const std::string& owner, const std::string& repo, int pr_number,
                            const std::string& body, const std::string& event,
                            const std::vector<std::string>& comments = {});
    std::vector<GiteaReview> list_reviews(const std::string& owner, const std::string& repo, int pr_number);
    GiteaReview get_review(const std::string& owner, const std::string& repo, int pr_number, int64_t review_id);
    void delete_review(const std::string& owner, const std::string& repo, int pr_number, int64_t review_id);
    void dismiss_review(const std::string& owner, const std::string& repo, int pr_number, 
                       int64_t review_id, const std::string& message);
    std::vector<GiteaReviewRequest> list_review_requests(const std::string& owner, const std::string& repo, int pr_number);
    void create_review_requests(const std::string& owner, const std::string& repo, int pr_number,
                              const std::vector<std::string>& reviewers,
                              const std::vector<std::string>& team_reviewers);
    void delete_review_requests(const std::string& owner, const std::string& repo, int pr_number,
                              const std::vector<std::string>& reviewers,
                              const std::vector<std::string>& team_reviewers);

    // Releases Management
    GiteaRelease create_release(const std::string& owner, const std::string& repo,
                              const std::string& tag_name, const std::string& name = "",
                              const std::string& body = "", bool is_draft = false,
                              bool is_prerelease = false, const std::string& target_commitish = "");
    std::vector<GiteaRelease> list_releases(const std::string& owner, const std::string& repo);
    GiteaRelease get_release(const std::string& owner, const std::string& repo, int64_t release_id);
    GiteaRelease get_release_by_tag(const std::string& owner, const std::string& repo, 
                                  const std::string& tag_name);
    GiteaRelease update_release(const std::string& owner, const std::string& repo, int64_t release_id,
                              const std::string& tag_name, const std::string& name,
                              const std::string& body, bool is_draft, bool is_prerelease,
                              const std::string& target_commitish);
    bool delete_release(const std::string& owner, const std::string& repo, int64_t release_id);

    // Tags Management
    std::vector<GiteaTag> list_tags(const std::string& owner, const std::string& repo);
    GiteaTag get_tag(const std::string& owner, const std::string& repo, const std::string& tag_name);
    GiteaTag create_tag(const std::string& owner, const std::string& repo,
                       const std::string& tag_name, const std::string& message,
                       const std::string& target_commitish);
    bool delete_tag(const std::string& owner, const std::string& repo, const std::string& tag_name);

    // File Operations
    GiteaFileResponse get_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                             const std::string& ref = "");
    std::vector<GiteaFileResponse> list_files(const std::string& owner, const std::string& repo,
                                            const std::string& path = "", const std::string& ref = "");
    GiteaFileResponse create_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                                const std::string& content, const std::string& message,
                                const std::string& branch = "", const std::string& author_name = "",
                                const std::string& author_email = "");
    GiteaFileResponse update_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                                const std::string& content, const std::string& message,
                                const std::string& sha, const std::string& branch = "",
                                const std::string& author_name = "", const std::string& author_email = "");
    bool delete_file(const std::string& owner, const std::string& repo, const std::string& file_path,
                   const std::string& message, const std::string& sha, const std::string& branch = "",
                   const std::string& author_name = "", const std::string& author_email = "");

    // Commits Management
    GiteaCommit get_commit(const std::string& owner, const std::string& repo, const std::string& sha);
    std::vector<GiteaCommit> list_commits(const std::string& owner, const std::string& repo,
                                        const std::string& sha = "", const std::string& path = "",
                                        const std::string& since = "", const std::string& until = "",
                                        int page = 1, int limit = 30);
    GiteaCommit create_commit(const std::string& owner, const std::string& repo,
                            const std::string& message, const std::string& tree_sha,
                            const std::vector<std::string>& parent_shas,
                            const GiteaUser& author, const GiteaUser& committer);

    // Milestones Management
    GiteaMilestone create_milestone(const std::string& owner, const std::string& repo,
                                  const std::string& title, const std::string& description = "",
                                  const std::string& due_date = "", const std::string& state = "open");
    std::vector<GiteaMilestone> list_milestones(const std::string& owner, const std::string& repo,
                                              const std::string& state = "");
    GiteaMilestone get_milestone(const std::string& owner, const std::string& repo, int64_t milestone_id);
    GiteaMilestone update_milestone(const std::string& owner, const std::string& repo, int64_t milestone_id,
                                  const std::string& title, const std::string& description = "",
                                  const std::string& due_date = "", const std::string& state = "");
    bool delete_milestone(const std::string& owner, const std::string& repo, int64_t milestone_id);

    // Labels Management
    GiteaLabel create_label(const std::string& owner, const std::string& repo,
                          const std::string& name, const std::string& color,
                          const std::string& description = "");
    std::vector<GiteaLabel> list_labels(const std::string& owner, const std::string& repo);
    GiteaLabel get_label(const std::string& owner, const std::string& repo, int64_t label_id);
    GiteaLabel update_label(const std::string& owner, const std::string& repo, int64_t label_id,
                          const std::string& name, const std::string& color,
                          const std::string& description = "");
    bool delete_label(const std::string& owner, const std::string& repo, int64_t label_id);

    // Organizations Management
    GiteaOrganization create_organization(const std::string& name, const std::string& full_name,
                                        const std::string& description = "", const std::string& website = "",
                                        const std::string& location = "", bool is_private = true);
    GiteaOrganization get_organization(const std::string& org);
    std::vector<GiteaOrganization> list_organizations(int page = 1, int limit = 30);
    GiteaOrganization update_organization(const std::string& org, const std::string& full_name = "",
                                        const std::string& description = "", const std::string& website = "",
                                        const std::string& location = "");
    bool delete_organization(const std::string& org);

    // Teams Management
    std::vector<GiteaTeam> list_teams(const std::string& org);
    GiteaTeam get_team(const std::string& org, int64_t team_id);
    GiteaTeam create_team(const std::string& org, const std::string& name,
                        const std::string& description = "", const std::string& permission = "read",
                        bool includes_all_repositories = false);
    GiteaTeam update_team(const std::string& org, int64_t team_id, const std::string& name,
                        const std::string& description = "", const std::string& permission = "read",
                        bool includes_all_repositories = false);
    bool delete_team(const std::string& org, int64_t team_id);
    std::vector<GiteaUser> list_team_members(const std::string& org, int64_t team_id);
    void add_team_member(const std::string& org, int64_t team_id, const std::string& username);
    void remove_team_member(const std::string& org, int64_t team_id, const std::string& username);
    std::vector<GiteaRepository> list_team_repositories(const std::string& org, int64_t team_id);
    void add_team_repository(const std::string& org, int64_t team_id, const std::string& owner, const std::string& repo);
    void remove_team_repository(const std::string& org, int64_t team_id, const std::string& owner, const std::string& repo);

    // Collaborators Management
    std::vector<GiteaUser> list_collaborators(const std::string& owner, const std::string& repo);
    void add_collaborator(const std::string& owner, const std::string& repo,
                         const std::string& username, const std::string& permission = "write");
    void remove_collaborator(const std::string& owner, const std::string& repo,
                           const std::string& username);
    std::string get_collaborator_permission(const std::string& owner, const std::string& repo,
                                          const std::string& username);

    // Webhooks Management
    GiteaWebhook create_webhook(const std::string& owner, const std::string& repo,
                              const std::string& url, const std::vector<std::string>& events,
                              const std::string& secret = "", const std::string& type = "gitea");
    std::vector<GiteaWebhook> list_webhooks(const std::string& owner, const std::string& repo);
    GiteaWebhook get_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);
    GiteaWebhook update_webhook(const std::string& owner, const std::string& repo, int64_t hook_id,
                              const std::string& url, const std::vector<std::string>& events,
                              const std::string& secret = "", const std::string& type = "gitea");
    bool delete_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);
    std::string test_webhook(const std::string& owner, const std::string& repo, int64_t hook_id);

    // Packages Management
    std::vector<GiteaPackage> list_packages(const std::string& owner, 
                                          const std::string& package_type = "");
    GiteaPackage get_package(const std::string& owner, const std::string& package_type,
                           const std::string& package_name);
    bool delete_package(const std::string& owner, const std::string& package_type,
                       const std::string& package_name);
    bool restore_package(const std::string& owner, const std::string& package_type,
                        const std::string& package_name);

    // Actions (CI/CD)
    std::vector<GiteaAction> list_actions(const std::string& owner, const std::string& repo,
                                        const std::string& ref = "", const std::string& workflow = "",
                                        const std::string& event = "", const std::string& status = "");
    GiteaAction get_action(const std::string& owner, const std::string& repo, int64_t run_id);
    bool cancel_action(const std::string& owner, const std::string& repo, int64_t run_id);
    bool rerun_action(const std::string& owner, const std::string& repo, int64_t run_id);
    std::string download_action_logs(const std::string& owner, const std::string& repo, int64_t run_id);

    // Notifications
    std::vector<GiteaNotification> list_notifications(const std::string& since = "",
                                                    bool all = false,
                                                    const std::vector<std::string>& statuses = {},
                                                    const std::vector<std::string>& subject_types = {});
    void mark_notifications_read(const std::string& last_read_at = "");
    void mark_thread_read(const std::string& owner, const std::string& repo, int64_t thread_id);

    // Wiki Management
    GiteaWikiPage create_wiki_page(const std::string& owner, const std::string& repo,
                                 const std::string& title, const std::string& content,
                                 const std::string& format = "markdown");
    GiteaWikiPage get_wiki_page(const std::string& owner, const std::string& repo, const std::string& page_name);
    std::vector<GiteaWikiPage> list_wiki_pages(const std::string& owner, const std::string& repo);
    GiteaWikiPage update_wiki_page(const std::string& owner, const std::string& repo, const std::string& page_name,
                                 const std::string& title = "", const std::string& content = "",
                                 const std::string& format = "markdown");
    bool delete_wiki_page(const std::string& owner, const std::string& repo, const std::string& page_name);

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

    // Administration (for site admins)
    struct GiteaServerStats {
        int users;
        int organizations;
        int repositories;
        int issues;
        int pull_requests;
        int milestones;
        int labels;
        int hooks;
        int releases;
        std::map<std::string, int> system_info;
    };

    GiteaServerStats get_server_stats();
    std::vector<GiteaUser> list_all_users(int page = 1, int limit = 30);
    std::vector<GiteaRepository> list_all_repositories(int page = 1, int limit = 30);
    std::vector<GiteaOrganization> list_all_organizations(int page = 1, int limit = 30);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    GiteaConfig config_;
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
    GiteaUser user_from_json(const nlohmann::json& json);
    GiteaRepository repository_from_json(const nlohmann::json& json);
    GiteaOrganization organization_from_json(const nlohmann::json& json);
    GiteaTeam team_from_json(const nlohmann::json& json);
    GiteaIssue issue_from_json(const nlohmann::json& json);
    GiteaPullRequest pull_request_from_json(const nlohmann::json& json);
    GiteaRelease release_from_json(const nlohmann::json& json);
    GiteaMilestone milestone_from_json(const nlohmann::json& json);
    GiteaLabel label_from_json(const nlohmann::json& json);
    GiteaComment comment_from_json(const nlohmann::json& json);
    GiteaReview review_from_json(const nlohmann::json& json);
    GiteaWebhook webhook_from_json(const nlohmann::json& json);
    GiteaPackage package_from_json(const nlohmann::json& json);
    GiteaAction action_from_json(const nlohmann::json& json);
    GiteaNotification notification_from_json(const nlohmann::json& json);
    GiteaWikiPage wiki_page_from_json(const nlohmann::json& json);
    GiteaFileResponse file_response_from_json(const nlohmann::json& json);
    GiteaBranch branch_from_json(const nlohmann::json& json);
    GiteaTag tag_from_json(const nlohmann::json& json);
    GiteaCommit commit_from_json(const nlohmann::json& json);
    GiteaReviewRequest review_request_from_json(const nlohmann::json& json);
};

#endif // GITEA_EXTENSION_H