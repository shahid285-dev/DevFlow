#ifndef GERRIT_EXTENSION_H
#define GERRIT_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class GerritExtension : public GitBase {
public:
    // Gerrit-specific data structures
    struct GerritAccount {
        int64_t _account_id;
        std::string name;
        std::string email;
        std::string username;
        std::vector<std::string> secondary_emails;
        std::string registered_on;
        bool inactive;
        std::vector<std::string> tags;
        std::map<std::string, std::string> avatars;
        std::vector<std::string> ssh_keys;
        bool more_accounts;
        std::string status;
        std::vector<std::string> groups;
    };

    struct GerritChange {
        std::string id;
        std::string project;
        std::string branch;
        std::string topic;
        std::string subject;
        GerritAccount owner;
        std::string url;
        std::string commit_message;
        std::string created;
        std::string updated;
        std::vector<GerritAccount> reviewers;
        std::vector<std::string> hashtags;
        std::map<std::string, int> labels;
        std::map<std::string, std::string> permitted_labels;
        bool removable_reviewers;
        std::string current_revision;
        std::map<std::string, GerritRevision> revisions;
        int _number;
        std::string status; // "NEW", "MERGED", "ABANDONED"
        bool work_in_progress;
        bool has_review_started;
        bool is_private;
        std::string submit_type; // "MERGE_IF_NECESSARY", "FAST_FORWARD_ONLY", "REBASE_IF_NECESSARY", "REBASE_ALWAYS", "MERGE_ALWAYS"
        std::string mergeable;
        int insertions;
        int deletions;
        int unresolved_comment_count;
        std::map<std::string, std::string> requirements;
        std::vector<std::string> submit_records;
    };

    struct GerritRevision {
        std::string kind; // "REWORK", "TRIVIAL_REBASE", "MERGE_FIRST_PARENT_UPDATE", "NO_CODE_CHANGE", "NO_CHANGE"
        int _number;
        GerritAccount uploader;
        std::string created;
        std::map<std::string, std::string> ref;
        std::map<std::string, GerritFileInfo> files;
        std::map<std::string, GerritCommit> commit;
        std::map<std::string, std::string> actions;
    };

    struct GerritFileInfo {
        std::string status; // "A", "D", "R", "C", "W", "M"
        bool binary;
        std::string old_path;
        int lines_inserted;
        int lines_deleted;
        int size_delta;
        int size;
    };

    struct GerritCommit {
        std::string commit;
        std::vector<std::string> parents;
        GerritAccount author;
        GerritAccount committer;
        std::string subject;
        std::string message;
    };

    struct GerritApproval {
        std::string tag;
        std::string category;
        int value;
        GerritAccount granted_by;
        std::string granted_on;
        int _account_id;
        int post_submit;
        std::string permitted_voting_range;
        std::string label;
    };

    struct GerritComment {
        std::string id;
        std::string path;
        int line;
        std::string in_reply_to;
        std::string message;
        GerritAccount author;
        std::string updated;
        std::string patch_set;
        std::map<std::string, std::string> side; // "REVISION", "PARENT"
        int range_start_line;
        int range_start_character;
        int range_end_line;
        int range_end_character;
        bool unresolved;
    };

    struct GerritProject {
        std::string id;
        std::string name;
        std::string parent;
        std::string description;
        std::string state; // "ACTIVE", "READ_ONLY", "HIDDEN"
        std::vector<std::string> branches;
        std::map<std::string, std::string> labels;
        std::vector<std::string> plugins;
        bool submit_type_editable;
        std::map<std::string, std::string> web_links;
        std::map<std::string, std::string> config;
    };

    struct GerritBranch {
        std::string ref;
        std::string revision;
        std::map<std::string, std::string> web_links;
    };

    struct GerritTag {
        std::string ref;
        std::string revision;
        GerritAccount created_by;
        std::string created;
        std::string message;
        bool can_delete;
    };

    struct GerritGroup {
        std::string id;
        std::string name;
        std::string description;
        int group_id;
        std::string owner;
        std::string owner_id;
        std::string created_on;
        std::vector<std::string> includes;
        std::vector<GerritAccount> members;
        std::map<std::string, std::string> options;
    };

    struct GerritPlugin {
        std::string id;
        std::string version;
        std::string index_url;
        std::string filename;
        bool disabled;
        std::map<std::string, std::string> js_files;
    };

    struct GerritDashboard {
        std::string id;
        std::string title;
        std::string project;
        std::string foreach;
        std::string url;
        std::vector<std::string> sections;
        std::map<std::string, std::string> definitions;
    };

    struct GerritDiffInfo {
        std::map<std::string, GerritDiffContent> content;
        std::vector<std::string> binary;
        std::vector<std::string> diff_header;
        std::map<std::string, int> intraline_status;
        std::string change_type; // "ADDED", "MODIFIED", "DELETED", "RENAMED", "COPIED"
        std::map<std::string, std::string> web_links;
    };

    struct GerritDiffContent {
        std::vector<std::string> a;
        std::vector<std::string> b;
        std::vector<GerritDiffIntralineInfo> ab;
        std::vector<bool> skip;
        std::vector<bool> common;
        std::vector<std::string> edit_a;
        std::vector<std::string> edit_b;
    };

    struct GerritDiffIntralineInfo {
        std::vector<int> skip;
        std::vector<int> mark;
        std::vector<int> move;
    };

    struct GerritMergeableInfo {
        std::string submit_type;
        std::string strategy;
        std::vector<std::string> mergeable;
        std::vector<std::string> commit_merged;
        std::vector<std::string> content_merged;
        std::vector<std::string> conflicts;
        std::vector<std::string> mergeable_into;
    };

    struct GerritSubmitRequirement {
        std::string name;
        std::string description;
        std::string status; // "SATISFIED", "UNSATISFIED", "OVERRIDDEN", "NOT_APPLICABLE", "ERROR"
        std::string fallback_text;
        std::vector<std::string> submittability_expression_result;
        std::map<std::string, std::string> override_expression_result;
    };

    struct GerritChangeMessage {
        std::string id;
        GerritAccount author;
        std::string date;
        std::string message;
        int _revision_number;
        std::map<std::string, std::string> tag;
        std::vector<GerritAccount> accounts_in_message;
    };

    struct GerritVotingRange {
        int min;
        int max;
    };

    // Authentication & Configuration
    struct GerritConfig {
        std::string base_url;
        std::string username;
        std::string password; // HTTP password or token
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
        bool use_digest_auth = true;
    };

    // Constructor & Configuration
    GerritExtension(const GerritConfig& config);
    virtual ~GerritExtension();

    void set_config(const GerritConfig& config);
    GerritConfig get_config() const;

    // Authentication
    bool authenticate();
    GerritAccount get_current_account();

    // Account Management
    GerritAccount get_account(int account_id);
    GerritAccount get_account_by_username(const std::string& username);
    GerritAccount get_account_by_email(const std::string& email);
    std::vector<GerritAccount> list_accounts(const std::string& query = "", bool suggest = false);
    GerritAccount create_account(const std::string& username, const std::string& name, 
                               const std::string& email, const std::string& ssh_key = "");
    GerritAccount update_account(int account_id, const std::string& name = "", 
                               const std::string& email = "", const std::string& status = "");
    std::vector<std::string> get_account_ssh_keys(int account_id);
    std::string add_account_ssh_key(int account_id, const std::string& ssh_key);
    bool delete_account_ssh_key(int account_id, const std::string& ssh_key_id);
    std::vector<GerritAccount> get_account_groups(int account_id);
    std::vector<GerritAccount> get_account_suggestions(const std::string& query);

    // Change Management (Code Reviews)
    GerritChange create_change(const std::string& project, const std::string& branch,
                             const std::string& subject, const std::string& topic = "",
                             const std::string& base_change = "", bool work_in_progress = false);
    GerritChange get_change(const std::string& change_id);
    GerritChange get_change_by_number(int change_number);
    std::vector<GerritChange> list_changes(const std::string& query = "", int limit = 25,
                                         int skip = 0, const std::string& option = "");
    GerritChange update_change(const std::string& change_id, const std::string& topic = "",
                             const std::string& commit_message = "", bool work_in_progress = false,
                             const std::string& assignee = "");
    bool abandon_change(const std::string& change_id, const std::string& message = "");
    bool restore_change(const std::string& change_id, const std::string& message = "");
    bool move_change(const std::string& change_id, const std::string& destination_branch);
    bool set_change_topic(const std::string& change_id, const std::string& topic);
    bool delete_change_topic(const std::string& change_id);
    bool set_change_assignee(const std::string& change_id, const std::string& assignee);
    bool delete_change_assignee(const std::string& change_id);
    bool set_change_hashtags(const std::string& change_id, const std::vector<std::string>& hashtags);
    bool add_change_hashtag(const std::string& change_id, const std::string& hashtag);
    bool remove_change_hashtag(const std::string& change_id, const std::string& hashtag);

    // Revision Management
    GerritRevision get_revision(const std::string& change_id, const std::string& revision_id);
    std::map<std::string, GerritRevision> list_revisions(const std::string& change_id);
    GerritRevision create_revision(const std::string& change_id, const std::string& base_revision,
                                 const std::map<std::string, std::string>& files);
    bool delete_revision(const std::string& change_id, const std::string& revision_id);
    bool rebase_revision(const std::string& change_id, const std::string& revision_id,
                        const std::string& base_revision = "");
    std::map<std::string, GerritFileInfo> list_revision_files(const std::string& change_id, 
                                                            const std::string& revision_id,
                                                            const std::string& parent = "1");
    GerritDiffInfo get_revision_diff(const std::string& change_id, const std::string& revision_id,
                                   const std::string& path, const std::string& parent = "1",
                                   int context = 3);
    std::string get_revision_file_content(const std::string& change_id, const std::string& revision_id,
                                        const std::string& path, const std::string& parent = "1");
    GerritMergeableInfo get_revision_mergeable(const std::string& change_id, const std::string& revision_id);

    // Review Management
    std::vector<GerritApproval> list_reviewers(const std::string& change_id);
    bool add_reviewer(const std::string& change_id, const std::string& reviewer);
    bool add_reviewers(const std::string& change_id, const std::vector<std::string>& reviewers);
    bool remove_reviewer(const std::string& change_id, const std::string& reviewer);
    std::vector<GerritApproval> list_revision_reviewers(const std::string& change_id, const std::string& revision_id);
    bool set_review(const std::string& change_id, const std::string& revision_id,
                   const std::map<std::string, int>& labels, const std::string& message = "",
                   const std::vector<GerritComment>& comments = {}, bool work_in_progress = false);
    bool submit_change(const std::string& change_id, const std::string& revision_id = "");
    bool publish_change(const std::string& change_id, const std::string& revision_id = "");

    // Comments Management
    std::vector<GerritComment> list_comments(const std::string& change_id);
    std::vector<GerritComment> list_revision_comments(const std::string& change_id, const std::string& revision_id);
    GerritComment create_comment(const std::string& change_id, const std::string& revision_id,
                               const std::string& path, int line, const std::string& message,
                               const std::string& in_reply_to = "");
    GerritComment update_comment(const std::string& change_id, const std::string& revision_id,
                               const std::string& comment_id, const std::string& message);
    bool delete_comment(const std::string& change_id, const std::string& revision_id,
                      const std::string& comment_id);
    bool set_comment_done(const std::string& change_id, const std::string& revision_id);
    bool mark_comment_resolved(const std::string& change_id, const std::string& revision_id,
                             const std::string& comment_id);
    bool mark_comment_unresolved(const std::string& change_id, const std::string& revision_id,
                               const std::string& comment_id);

    // Draft Comments Management
    std::vector<GerritComment> list_draft_comments(const std::string& change_id);
    std::vector<GerritComment> list_revision_draft_comments(const std::string& change_id, const std::string& revision_id);
    GerritComment create_draft_comment(const std::string& change_id, const std::string& revision_id,
                                     const std::string& path, int line, const std::string& message,
                                     const std::string& in_reply_to = "");
    GerritComment update_draft_comment(const std::string& change_id, const std::string& revision_id,
                                     const std::string& comment_id, const std::string& message);
    bool delete_draft_comment(const std::string& change_id, const std::string& revision_id,
                            const std::string& comment_id);
    bool publish_draft_comments(const std::string& change_id, const std::string& revision_id);

    // Project Management
    GerritProject create_project(const std::string& name, const std::string& parent = "",
                               const std::string& description = "", const std::string& submit_type = "MERGE_IF_NECESSARY",
                               bool create_empty_commit = false);
    GerritProject get_project(const std::string& project_name);
    std::vector<GerritProject> list_projects(const std::string& query = "", const std::string& type = "ALL",
                                           bool description = false, int limit = 25, int skip = 0);
    GerritProject update_project(const std::string& project_name, const std::string& description = "",
                               const std::string& submit_type = "", const std::string& state = "");
    bool delete_project(const std::string& project_name);
    std::map<std::string, std::string> get_project_config(const std::string& project_name);
    bool set_project_config(const std::string& project_name, const std::map<std::string, std::string>& config);
    std::vector<std::string> get_project_access_rights(const std::string& project_name);
    bool set_project_access_rights(const std::string& project_name, const std::map<std::string, std::string>& access_rights);

    // Branch Management
    GerritBranch create_branch(const std::string& project_name, const std::string& branch_name,
                             const std::string& revision);
    GerritBranch get_branch(const std::string& project_name, const std::string& branch_name);
    std::vector<GerritBranch> list_branches(const std::string& project_name, const std::string& limit = "",
                                          const std::string& skip = "", const std::string& regex = "");
    bool delete_branch(const std::string& project_name, const std::string& branch_name);
    GerritBranch get_branch_revision(const std::string& project_name, const std::string& branch_name);
    bool set_branch_revision(const std::string& project_name, const std::string& branch_name,
                           const std::string& revision);

    // Tag Management
    GerritTag create_tag(const std::string& project_name, const std::string& tag_name,
                       const std::string& revision, const std::string& message = "");
    GerritTag get_tag(const std::string& project_name, const std::string& tag_name);
    std::vector<GerritTag> list_tags(const std::string& project_name, const std::string& limit = "",
                                   const std::string& skip = "", const std::string& regex = "");
    bool delete_tag(const std::string& project_name, const std::string& tag_name);

    // Group Management
    GerritGroup create_group(const std::string& name, const std::string& description = "",
                           const std::string& owner = "");
    GerritGroup get_group(const std::string& group_id);
    GerritGroup get_group_by_name(const std::string& group_name);
    std::vector<GerritGroup> list_groups(const std::string& query = "", bool owned = false);
    GerritGroup update_group(const std::string& group_id, const std::string& name = "",
                           const std::string& description = "", const std::string& owner = "");
    bool delete_group(const std::string& group_id);
    std::vector<GerritAccount> list_group_members(const std::string& group_id);
    bool add_group_member(const std::string& group_id, const std::string& account_id);
    bool remove_group_member(const std::string& group_id, const std::string& account_id);
    std::vector<GerritGroup> list_group_subgroups(const std::string& group_id);
    bool add_group_subgroup(const std::string& group_id, const std::string& subgroup_id);
    bool remove_group_subgroup(const std::string& group_id, const std::string& subgroup_id);

    // Plugin Management
    std::vector<GerritPlugin> list_plugins(const std::string& project_name = "");
    GerritPlugin get_plugin(const std::string& plugin_name);
    bool install_plugin(const std::string& plugin_name, const std::string& plugin_file);
    bool enable_plugin(const std::string& plugin_name, const std::string& project_name = "");
    bool disable_plugin(const std::string& plugin_name, const std::string& project_name = "");
    bool reload_plugin(const std::string& plugin_name);

    // Dashboard Management
    GerritDashboard create_dashboard(const std::string& project, const std::string& title,
                                   const std::string& foreach, const std::vector<std::string>& sections);
    GerritDashboard get_dashboard(const std::string& dashboard_id);
    std::vector<GerritDashboard> list_dashboards(const std::string& project = "");
    GerritDashboard update_dashboard(const std::string& dashboard_id, const std::string& title = "",
                                   const std::string& foreach = "", const std::vector<std::string>& sections = {});
    bool delete_dashboard(const std::string& dashboard_id);

    // Change Messages
    std::vector<GerritChangeMessage> list_change_messages(const std::string& change_id);
    GerritChangeMessage create_change_message(const std::string& change_id, const std::string& message,
                                            const std::string& tag = "");

    // Submit Requirements
    std::vector<GerritSubmitRequirement> list_submit_requirements(const std::string& change_id);
    GerritSubmitRequirement get_submit_requirement(const std::string& change_id, const std::string& requirement_name);

    // Voting and Labels
    std::map<std::string, GerritVotingRange> get_permitted_labels(const std::string& change_id);
    std::map<std::string, std::vector<int>> get_label_details(const std::string& change_id, const std::string& label_name);

    // Search
    struct SearchResult {
        std::vector<GerritChange> changes;
        std::vector<GerritAccount> accounts;
        std::vector<GerritProject> projects;
        std::vector<GerritGroup> groups;
        bool more_changes;
        int total_change_count;
    };

    SearchResult search_changes(const std::string& query, int limit = 25, int skip = 0);
    SearchResult search_accounts(const std::string& query, int limit = 25, int skip = 0);
    SearchResult search_projects(const std::string& query, int limit = 25, int skip = 0);
    SearchResult search_groups(const std::string& query, int limit = 25, int skip = 0);

    // Repository Operations with Gerrit enhancements
    void clone_gerrit_project(const std::string& project_name, const std::string& local_path,
                            const std::function<bool(size_t, size_t)>& progress_callback = {});
    void push_for_review(const std::string& local_path, const std::string& branch,
                        const std::string& remote = "origin", bool draft = false);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    GerritConfig config_;
    std::mutex api_mutex_;
    std::map<std::string, nlohmann::json> cache_;
    
    // HTTP client implementation
    std::string make_request(const std::string& method, const std::string& url, 
                           const std::string& data = "");
    void handle_http_error(int status_code, const std::string& response);
    
    // Cache management
    void cache_set(const std::string& key, const nlohmann::json& value);
    std::optional<nlohmann::json> cache_get(const std::string& key);
    void cache_clear();
    
    // Helper methods for data conversion
    GerritAccount account_from_json(const nlohmann::json& json);
    GerritChange change_from_json(const nlohmann::json& json);
    GerritRevision revision_from_json(const nlohmann::json& json);
    GerritFileInfo file_info_from_json(const nlohmann::json& json);
    GerritCommit commit_from_json(const nlohmann::json& json);
    GerritApproval approval_from_json(const nlohmann::json& json);
    GerritComment comment_from_json(const nlohmann::json& json);
    GerritProject project_from_json(const nlohmann::json& json);
    GerritBranch branch_from_json(const nlohmann::json& json);
    GerritTag tag_from_json(const nlohmann::json& json);
    GerritGroup group_from_json(const nlohmann::json& json);
    GerritPlugin plugin_from_json(const nlohmann::json& json);
    GerritDashboard dashboard_from_json(const nlohmann::json& json);
    GerritDiffInfo diff_info_from_json(const nlohmann::json& json);
    GerritDiffContent diff_content_from_json(const nlohmann::json& json);
    GerritDiffIntralineInfo diff_intraline_info_from_json(const nlohmann::json& json);
    GerritMergeableInfo mergeable_info_from_json(const nlohmann::json& json);
    GerritSubmitRequirement submit_requirement_from_json(const nlohmann::json& json);
    GerritChangeMessage change_message_from_json(const nlohmann::json& json);
    GerritVotingRange voting_range_from_json(const nlohmann::json& json);
};

#endif // GERRIT_EXTENSION_H