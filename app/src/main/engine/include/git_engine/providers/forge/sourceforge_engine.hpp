#ifndef SOURCEFORGE_EXTENSION_H
#define SOURCEFORGE_EXTENSION_H

#include "GitBase.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>

class SourceForgeExtension : public GitBase {
public:
    struct SourceForgeUser {
        std::string username;
        std::string name;
        std::string url;
        std::string created;
        std::string country;
        std::string language;
        std::string timezone;
        std::map<std::string, std::string> links;
        std::vector<std::string> skills;
        std::string biography;
        std::string homepage;
        std::string company;
        bool is_admin;
        bool is_toolbox_user;
    };

    struct SourceForgeProject {
        std::string name;
        std::string title;
        std::string summary;
        std::string description;
        std::string category;
        std::string trove_categories;
        std::string unixname;
        std::string url;
        std::string created;
        std::string updated;
        std::string logo_url;
        std::string icon_url;
        SourceForgeUser owner;
        std::vector<SourceForgeUser> developers;
        std::vector<SourceForgeUser> administrators;
        std::vector<std::string> labels;
        std::map<std::string, int> stats;
        std::map<std::string, std::string> links;
        bool is_public;
        bool is_active;
        std::string status; // "active", "inactive", "abandoned"
        std::string license;
        std::string programming_language;
        std::string operating_system;
        std::string topic;
        std::string audience;
    };

    struct SourceForgeRelease {
        std::string filename;
        std::string version;
        std::string date;
        std::string summary;
        std::string description;
        std::string change_log;
        std::string download_url;
        std::string browse_url;
        std::string size;
        std::string md5;
        std::string sha1;
        std::string sha256;
        std::string os;
        std::string type; // "source", "binary", "documentation", "other"
        std::string architecture;
        int downloads;
        std::vector<std::string> mirrors;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeDownload {
        std::string filename;
        std::string url;
        std::string size;
        std::string summary;
        std::string date;
        std::string md5;
        std::string sha1;
        std::string os;
        std::string type;
        std::string architecture;
        int downloads;
        std::vector<std::string> mirrors;
    };

    struct SourceForgeTroveCategory {
        std::string id;
        std::string fullname;
        std::string shortname;
        std::string description;
        std::vector<std::string> parents;
        std::vector<std::string> children;
    };

    struct SourceForgeTracker {
        std::string name;
        std::string summary;
        std::string description;
        std::string status; // "open", "closed"
        int open_count;
        int closed_count;
        int total_count;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeTicket {
        int id;
        std::string summary;
        std::string description;
        std::string status; // "open", "closed", "pending"
        std::string priority; // "low", "medium", "high", "urgent"
        std::string category;
        std::string group;
        std::string assigned_to;
        SourceForgeUser reported_by;
        std::string created;
        std::string updated;
        std::string closed;
        std::vector<std::string> labels;
        std::vector<SourceForgeComment> comments;
        std::map<std::string, std::string> custom_fields;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeComment {
        int id;
        std::string text;
        SourceForgeUser author;
        std::string created;
        std::string updated;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeDiscussion {
        int id;
        std::string subject;
        std::string body;
        std::string forum;
        SourceForgeUser author;
        std::string created;
        std::string updated;
        int reply_count;
        int view_count;
        bool is_sticky;
        bool is_locked;
        std::vector<SourceForgeComment> replies;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeForum {
        std::string name;
        std::string description;
        std::string status; // "active", "readonly", "archived"
        int topic_count;
        int post_count;
        std::string created;
        std::string updated;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeWikiPage {
        std::string name;
        std::string title;
        std::string content;
        std::string format; // "textile", "markdown", "creole"
        SourceForgeUser author;
        std::string created;
        std::string updated;
        int version;
        std::vector<std::string> tags;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeGitRepository {
        std::string name;
        std::string description;
        std::string url;
        std::string clone_url;
        std::string browse_url;
        std::string created;
        std::string updated;
        std::string default_branch;
        bool is_private;
        int size;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeSvnRepository {
        std::string name;
        std::string url;
        std::string browse_url;
        std::string created;
        std::string updated;
        int revision;
        int size;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeHgRepository {
        std::string name;
        std::string description;
        std::string url;
        std::string clone_url;
        std::string browse_url;
        std::string created;
        std::string updated;
        std::string tip;
        bool is_private;
        int size;
        std::map<std::string, std::string> links;
    };

    struct SourceForgeStats {
        std::map<std::string, int> downloads;
        std::map<std::string, int> page_views;
        std::map<std::string, int> unique_visitors;
        std::map<std::string, int> rank;
        std::map<std::string, std::string> trends;
    };

    struct SourceForgeMirror {
        std::string name;
        std::string url;
        std::string country;
        std::string continent;
        std::string status; // "up", "down", "syncing"
        int latency;
        std::string last_sync;
        std::map<std::string, std::string> protocols;
    };

    struct SourceForgeMailingList {
        std::string name;
        std::string description;
        std::string type; // "users", "developers", "announce", "commits"
        std::string status; // "active", "inactive", "moderated"
        std::string archive_url;
        std::string subscribe_url;
        std::string unsubscribe_url;
        std::string post_url;
        std::string admin_url;
        int subscriber_count;
        std::map<std::string, std::string> links;
    };

    // Authentication & Configuration
    struct SourceForgeConfig {
        std::string base_url = "https://sourceforge.net/rest";
        std::string username;
        std::string api_key;
        int timeout_seconds = 30;
        int retry_attempts = 3;
        bool enable_caching = true;
    };

    // Constructor & Configuration
    SourceForgeExtension(const SourceForgeConfig& config);
    virtual ~SourceForgeExtension();

    void set_config(const SourceForgeConfig& config);
    SourceForgeConfig get_config() const;

    // Authentication & Rate Limiting
    bool authenticate();
    struct RateLimitInfo get_rate_limit();
    bool is_rate_limited();

    // User Management
    SourceForgeUser get_current_user();
    SourceForgeUser get_user(const std::string& username);
    std::vector<SourceForgeUser> search_users(const std::string& query);
    SourceForgeUser update_user_profile(const std::string& name = "", const std::string& biography = "",
                                      const std::string& homepage = "", const std::string& company = "",
                                      const std::string& country = "", const std::string& language = "",
                                      const std::string& timezone = "");

    // Project Management
    SourceForgeProject create_project(const std::string& name, const std::string& title,
                                    const std::string& description, const std::string& category,
                                    const std::string& license = "", bool is_public = true);
    SourceForgeProject get_project(const std::string& project_name);
    std::vector<SourceForgeProject> list_user_projects(const std::string& username = "");
    std::vector<SourceForgeProject> search_projects(const std::string& query, const std::string& category = "",
                                                  const std::string& topic = "", const std::string& language = "");
    SourceForgeProject update_project(const std::string& project_name, const std::string& title = "",
                                    const std::string& description = "", const std::string& category = "",
                                    const std::string& license = "", const std::string& status = "");
    bool delete_project(const std::string& project_name);
    bool join_project(const std::string& project_name);
    bool leave_project(const std::string& project_name);

    // Project Members & Permissions
    std::vector<SourceForgeUser> list_project_developers(const std::string& project_name);
    std::vector<SourceForgeUser> list_project_administrators(const std::string& project_name);
    bool add_project_developer(const std::string& project_name, const std::string& username);
    bool remove_project_developer(const std::string& project_name, const std::string& username);
    bool add_project_administrator(const std::string& project_name, const std::string& username);
    bool remove_project_administrator(const std::string& project_name, const std::string& username);

    // Releases & Downloads Management
    SourceForgeRelease create_release(const std::string& project_name, const std::string& filename,
                                    const std::string& version, const std::string& summary,
                                    const std::string& description = "", const std::string& change_log = "",
                                    const std::string& os = "", const std::string& type = "binary");
    std::vector<SourceForgeRelease> list_releases(const std::string& project_name);
    SourceForgeRelease get_release(const std::string& project_name, const std::string& filename);
    SourceForgeRelease update_release(const std::string& project_name, const std::string& filename,
                                    const std::string& version = "", const std::string& summary = "",
                                    const std::string& description = "", const std::string& change_log = "");
    bool delete_release(const std::string& project_name, const std::string& filename);
    std::vector<SourceForgeDownload> list_downloads(const std::string& project_name);
    SourceForgeStats get_download_stats(const std::string& project_name);

    // File Upload & Download
    bool upload_file(const std::string& project_name, const std::string& local_file_path,
                   const std::string& remote_filename, const std::string& version = "",
                   const std::string& summary = "", const std::string& description = "");
    bool download_file(const std::string& project_name, const std::string& filename,
                     const std::string& local_path, const std::function<bool(size_t, size_t)>& progress_callback = {});
    std::vector<SourceForgeMirror> list_mirrors(const std::string& project_name);

    // Git Repository Management
    SourceForgeGitRepository get_git_repository(const std::string& project_name);
    bool create_git_repository(const std::string& project_name, const std::string& description = "");
    bool delete_git_repository(const std::string& project_name);
    void clone_sourceforge_git(const std::string& project_name, const std::string& local_path,
                             const std::function<bool(size_t, size_t)>& progress_callback = {});

    // SVN Repository Management
    SourceForgeSvnRepository get_svn_repository(const std::string& project_name);
    bool create_svn_repository(const std::string& project_name);
    bool delete_svn_repository(const std::string& project_name);

    // Mercurial Repository Management
    SourceForgeHgRepository get_hg_repository(const std::string& project_name);
    bool create_hg_repository(const std::string& project_name, const std::string& description = "");
    bool delete_hg_repository(const std::string& project_name);

    // Ticket (Bug) Tracking
    SourceForgeTicket create_ticket(const std::string& project_name, const std::string& summary,
                                  const std::string& description, const std::string& category = "bugs",
                                  const std::string& priority = "medium", const std::string& assigned_to = "");
    SourceForgeTicket get_ticket(const std::string& project_name, int ticket_id);
    std::vector<SourceForgeTicket> list_tickets(const std::string& project_name, const std::string& status = "",
                                              const std::string& category = "", const std::string& assigned_to = "");
    SourceForgeTicket update_ticket(const std::string& project_name, int ticket_id, const std::string& summary = "",
                                  const std::string& description = "", const std::string& status = "",
                                  const std::string& priority = "", const std::string& assigned_to = "");
    bool delete_ticket(const std::string& project_name, int ticket_id);
    std::vector<SourceForgeTracker> list_trackers(const std::string& project_name);

    // Ticket Comments
    SourceForgeComment create_ticket_comment(const std::string& project_name, int ticket_id, const std::string& text);
    std::vector<SourceForgeComment> list_ticket_comments(const std::string& project_name, int ticket_id);
    SourceForgeComment update_ticket_comment(const std::string& project_name, int ticket_id, int comment_id, const std::string& text);
    bool delete_ticket_comment(const std::string& project_name, int ticket_id, int comment_id);

    // Discussion Forums
    SourceForgeDiscussion create_discussion(const std::string& project_name, const std::string& forum,
                                          const std::string& subject, const std::string& body);
    SourceForgeDiscussion get_discussion(const std::string& project_name, int discussion_id);
    std::vector<SourceForgeDiscussion> list_discussions(const std::string& project_name, const std::string& forum = "");
    SourceForgeDiscussion update_discussion(const std::string& project_name, int discussion_id,
                                          const std::string& subject = "", const std::string& body = "");
    bool delete_discussion(const std::string& project_name, int discussion_id);
    std::vector<SourceForgeForum> list_forums(const std::string& project_name);

    // Forum Replies
    SourceForgeComment create_discussion_reply(const std::string& project_name, int discussion_id, const std::string& text);
    std::vector<SourceForgeComment> list_discussion_replies(const std::string& project_name, int discussion_id);
    SourceForgeComment update_discussion_reply(const std::string& project_name, int discussion_id, int reply_id, const std::string& text);
    bool delete_discussion_reply(const std::string& project_name, int discussion_id, int reply_id);

    // Wiki Management
    SourceForgeWikiPage create_wiki_page(const std::string& project_name, const std::string& page_name,
                                       const std::string& title, const std::string& content,
                                       const std::string& format = "markdown");
    SourceForgeWikiPage get_wiki_page(const std::string& project_name, const std::string& page_name);
    std::vector<SourceForgeWikiPage> list_wiki_pages(const std::string& project_name);
    SourceForgeWikiPage update_wiki_page(const std::string& project_name, const std::string& page_name,
                                       const std::string& title = "", const std::string& content = "",
                                       const std::string& format = "markdown");
    bool delete_wiki_page(const std::string& project_name, const std::string& page_name);
    std::vector<SourceForgeWikiPage> get_wiki_page_history(const std::string& project_name, const std::string& page_name);

    // Mailing Lists
    SourceForgeMailingList create_mailing_list(const std::string& project_name, const std::string& name,
                                             const std::string& description, const std::string& type = "users");
    std::vector<SourceForgeMailingList> list_mailing_lists(const std::string& project_name);
    SourceForgeMailingList get_mailing_list(const std::string& project_name, const std::string& list_name);
    SourceForgeMailingList update_mailing_list(const std::string& project_name, const std::string& list_name,
                                             const std::string& description = "", const std::string& type = "");
    bool delete_mailing_list(const std::string& project_name, const std::string& list_name);
    bool subscribe_to_mailing_list(const std::string& project_name, const std::string& list_name);
    bool unsubscribe_from_mailing_list(const std::string& project_name, const std::string& list_name);

    // Trove Categories
    std::vector<SourceForgeTroveCategory> list_trove_categories();
    SourceForgeTroveCategory get_trove_category(const std::string& category_id);
    std::vector<SourceForgeProject> list_projects_in_category(const std::string& category_id);
    bool add_project_to_category(const std::string& project_name, const std::string& category_id);
    bool remove_project_from_category(const std::string& project_name, const std::string& category_id);

    // Statistics & Analytics
    SourceForgeStats get_project_stats(const std::string& project_name);
    SourceForgeStats get_user_stats(const std::string& username = "");
    std::map<std::string, int> get_daily_downloads(const std::string& project_name, const std::string& start_date, const std::string& end_date);
    std::map<std::string, int> get_daily_page_views(const std::string& project_name, const std::string& start_date, const std::string& end_date);

    // Project Labels & Tags
    std::vector<std::string> list_project_labels(const std::string& project_name);
    bool add_project_label(const std::string& project_name, const std::string& label);
    bool remove_project_label(const std::string& project_name, const std::string& label);

    // Project Settings
    bool update_project_settings(const std::string& project_name, bool enable_downloads = true,
                              bool enable_discussions = true, bool enable_wiki = true,
                              bool enable_tickets = true, bool enable_mailing_lists = true,
                              bool enable_svn = true, bool enable_git = true, bool enable_hg = true);
    std::map<std::string, bool> get_project_settings(const std::string& project_name);

    // Featured Projects
    std::vector<SourceForgeProject> get_featured_projects();
    std::vector<SourceForgeProject> get_trending_projects();
    std::vector<SourceForgeProject> get_freshmeat_projects();

    // Project Rankings
    std::vector<SourceForgeProject> get_top_downloaded_projects(int limit = 10);
    std::vector<SourceForgeProject> get_top_rated_projects(int limit = 10);
    std::vector<SourceForgeProject> get_most_active_projects(int limit = 10);

    // Utility Methods
    std::string get_api_url(const std::string& endpoint) const;
    nlohmann::json api_get(const std::string& endpoint);
    nlohmann::json api_post(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_put(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_patch(const std::string& endpoint, const nlohmann::json& data);
    nlohmann::json api_delete(const std::string& endpoint);

private:
    SourceForgeConfig config_;
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
    
    // File upload helper
    bool upload_file_multipart(const std::string& url, const std::string& file_path, 
                             const std::map<std::string, std::string>& form_data);
    
    // Helper methods for data conversion
    SourceForgeUser user_from_json(const nlohmann::json& json);
    SourceForgeProject project_from_json(const nlohmann::json& json);
    SourceForgeRelease release_from_json(const nlohmann::json& json);
    SourceForgeDownload download_from_json(const nlohmann::json& json);
    SourceForgeTroveCategory trove_category_from_json(const nlohmann::json& json);
    SourceForgeTracker tracker_from_json(const nlohmann::json& json);
    SourceForgeTicket ticket_from_json(const nlohmann::json& json);
    SourceForgeComment comment_from_json(const nlohmann::json& json);
    SourceForgeDiscussion discussion_from_json(const nlohmann::json& json);
    SourceForgeForum forum_from_json(const nlohmann::json& json);
    SourceForgeWikiPage wiki_page_from_json(const nlohmann::json& json);
    SourceForgeGitRepository git_repository_from_json(const nlohmann::json& json);
    SourceForgeSvnRepository svn_repository_from_json(const nlohmann::json& json);
    SourceForgeHgRepository hg_repository_from_json(const nlohmann::json& json);
    SourceForgeStats stats_from_json(const nlohmann::json& json);
    SourceForgeMirror mirror_from_json(const nlohmann::json& json);
    SourceForgeMailingList mailing_list_from_json(const nlohmann::json& json);
};

#endif // SOURCEFORGE_EXTENSION_H