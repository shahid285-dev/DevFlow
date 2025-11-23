#ifndef GIT_BASE_H
#define GIT_BASE_H

#include <git2.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <stdexcept>
#include <atomic>
#include <mutex>

class GitException : public std::runtime_error {
public:
    explicit GitException(const std::string& message, int error_code = -1);
    int error_code() const;

private:
    int error_code_;
};

struct ProgressData {
    std::function<bool(size_t, size_t)> transfer_progress;
    std::function<bool(const std::string&, size_t, size_t)> checkout_progress;
    std::function<bool(const std::string&)> sideband_progress;
    std::atomic<bool> cancelled{false};
};

class GitBase {
public:
    struct Signature {
        std::string name;
        std::string email;
        git_time time;
        
        Signature(const std::string& name, const std::string& email);
        Signature(const git_signature* sig);
    };

    struct CommitInfo {
        std::string id;
        std::string message;
        Signature author;
        Signature committer;
        std::vector<std::string> parent_ids;
    };

    struct BranchInfo {
        std::string name;
        std::string commit_id;
        bool is_remote;
        bool is_head;
    };

    struct RemoteInfo {
        std::string name;
        std::string url;
        std::vector<std::string> push_urls;
    };

    struct DiffStats {
        size_t files_changed;
        size_t insertions;
        size_t deletions;
    };

    struct StatusEntry {
        std::string path;
        git_status_t status;
        git_delta_t index_delta;
        git_delta_t workdir_delta;
    };

    struct ConfigEntry {
        std::string name;
        std::string value;
        git_config_level_t level;
    };

    struct SubmoduleInfo {
        std::string name;
        std::string path;
        std::string url;
        git_submodule_ignore_t ignore;
        git_submodule_update_t update_strategy;
        git_submodule_recurse_t fetch_recurse;
    };

    struct WorktreeInfo {
        std::string name;
        std::string path;
        std::string head_id;
        bool is_locked;
        std::string lock_reason;
    };

    struct BlameHunk {
        size_t lines_in_hunk;
        std::string final_commit_id;
        std::string final_signature;
        std::string orig_commit_id;
        std::string orig_path;
        size_t orig_start_line;
        size_t final_start_line;
    };

    struct Note {
        std::string commit_id;
        std::string namespace_;
        std::string message;
        Signature author;
    };

    struct ReflogEntry {
        std::string old_id;
        std::string new_id;
        Signature committer;
        std::string message;
        
        ReflogEntry(const std::string& old, const std::string& new_, const Signature& comm, const std::string& msg);
    };

    struct PackBuilderProgress {
        size_t stage;
        size_t current;
        size_t total;
    };

    struct TransportMessage {
        std::string message;
        git_direction_t direction;
    };

    struct GraphAheadBehind {
        size_t ahead;
        size_t behind;
    };

    struct MergeOptions {
        git_merge_file_favor_t file_favor;
        git_merge_flag_t flags;
        unsigned int rename_threshold;
        unsigned int target_limit;
        
        MergeOptions();
    };

    struct IndexTime {
        int64_t seconds;
        uint32_t nanoseconds;
    };

    struct IndexEntry {
        std::string path;
        git_oid oid;
        git_filemode_t mode;
        IndexTime ctime;
        IndexTime mtime;
        uint32_t dev;
        uint32_t ino;
        uint32_t uid;
        uint32_t gid;
        uint64_t file_size;
        git_oid id;
    };

    // Constructor & Destructor
    GitBase();
    virtual ~GitBase();
    GitBase(const GitBase&) = delete;
    GitBase& operator=(const GitBase&) = delete;

    // Core Repository Operations
    void clone_repository(const std::string& url, const std::string& local_path,
                         const std::function<bool(size_t, size_t)>& transfer_progress = {},
                         const std::function<bool(const std::string&, size_t, size_t)>& checkout_progress = {},
                         const std::function<bool(const std::string&)>& sideband_progress = {});
    void init_repository(const std::string& path, bool is_bare = false);
    void open_repository(const std::string& path);
    std::string discover_repository(const std::string& start_path = ".", bool across_fs = false);
    void cleanup();

    // Object Database Operations
    std::string create_blob(const std::string& content);
    std::string create_blob_from_file(const std::string& file_path);
    std::string get_blob_content(const std::string& blob_id);
    std::string create_tree(const std::vector<git_tree_entry>& entries);
    std::vector<std::string> get_tree_entries(const std::string& tree_id);
    std::string create_commit(const std::string& tree_id, 
                             const std::vector<std::string>& parent_ids,
                             const Signature& author, 
                             const Signature& committer,
                             const std::string& message);

    // Object Database Extensions
    bool object_exists(const std::string& object_id);
    git_object_t object_type(const std::string& object_id);
    size_t object_size(const std::string& object_id);
    std::string object_short_id(const std::string& object_id);
    void object_stream(const std::string& object_id, std::function<bool(const char*, size_t)> stream_callback);
    bool is_object_loose(const std::string& object_id);
    std::vector<std::string> list_objects();
    size_t object_cache_size();
    void set_object_cache_size(size_t size);
    void prune_packfiles();
    bool object_database_has_alternates();
    void add_object_database_alternate(const std::string& path);

    // Reference Management
    std::vector<BranchInfo> list_branches(git_branch_t branch_type = GIT_BRANCH_ALL);
    void create_branch(const std::string& branch_name, const std::string& start_point = "");
    void delete_branch(const std::string& branch_name, bool is_remote = false);

    // Index/Staging Area Operations
    void stage_files(const std::vector<std::string>& paths);
    void unstage_files(const std::vector<std::string>& paths);
    std::vector<StatusEntry> get_status(git_status_options* opts = nullptr);

    // Index Advanced Operations
    std::vector<IndexEntry> get_index_entries();
    void update_index_entry(const std::string& path, const git_oid& oid, git_filemode_t mode);
    void remove_index_entry(const std::string& path);
    bool index_has_conflicts();
    std::vector<std::tuple<std::string, std::string, std::string>> get_index_conflicts();
    void resolve_index_conflict(const std::string& path);
    void clear_index_conflicts();
    void read_tree_into_index(const std::string& tree_id);
    git_oid write_tree_from_index();
    void set_index_caps(int caps);
    size_t index_entrycount();

    // Config System
    void set_config_string(const std::string& name, const std::string& value, 
                          git_config_level_t level = GIT_CONFIG_LEVEL_LOCAL);
    std::string get_config_string(const std::string& name);
    std::vector<ConfigEntry> get_config_entries(const std::string& regex = ".*");

    // Diff Operations
    DiffStats get_diff_stats(const std::string& from_commit = "", const std::string& to_commit = "");
    std::string generate_patch(const std::string& from_commit = "", const std::string& to_commit = "");

    // Diff Advanced Operations
    std::string generate_diff_stats_format(git_diff_stats_format_t format);
    std::vector<std::string> get_diff_delta_paths(const std::string& from_commit = "", const std::string& to_commit = "");
    void find_similar_in_diff(git_diff* diff, git_diff_find_options_t options);
    size_t get_diff_num_deltas(const std::string& from_commit = "", const std::string& to_commit = "");
    size_t get_diff_num_deltas_of_type(git_delta_t type, const std::string& from_commit = "", const std::string& to_commit = "");
    std::string get_diff_patch_for_delta(const std::string& from_commit, const std::string& to_commit, size_t delta_index);
    void set_diff_context_lines(size_t context_lines);
    void set_diff_interhunk_lines(size_t interhunk_lines);

    // Merge & Rebase Operations
    void merge(const std::string& branch_name, 
               const std::function<bool(const git_merge_file_result*)>& merge_conflict_callback = {});
    void rebase(const std::string& upstream, const std::string& branch = "",
                const std::function<bool(const git_merge_file_result*)>& conflict_callback = {});

    // Merge Analysis & Advanced Operations
    git_merge_analysis_t analyze_merge(const std::string& branch_name);
    git_merge_preference_t get_merge_preference();
    bool is_merge_fastforward_possible(const std::string& branch_name);
    std::string find_merge_base(const std::string& commit1, const std::string& commit2);
    std::vector<std::string> find_merge_bases(const std::string& commit1, const std::string& commit2);
    std::vector<std::string> find_merge_bases_many(const std::vector<std::string>& commits);
    void set_merge_strategy(git_merge_strategy_t strategy);
    void set_merge_file_favor(git_merge_file_favor_t favor);
    git_merge_file_result merge_files(const std::string& our_path, const std::string& our_content,
                                     const std::string& their_path, const std::string& their_content,
                                     const std::string& base_path = "", const std::string& base_content = "");

    // Remote Operations with Progress Tracking
    void fetch(const std::string& remote_name = "origin",
               const std::function<bool(size_t, size_t)>& transfer_progress = {},
               const std::function<bool(const std::string&)>& sideband_progress = {});
    void push(const std::string& remote_name = "origin", 
              const std::vector<std::string>& refspecs = {},
              const std::function<bool(size_t, size_t)>& push_progress = {},
              const std::function<bool(const std::string&)>& sideband_progress = {});

    // Network & Transport Operations
    void set_remote_authentication_callback(std::function<int(git_credential** cred, const char* url, 
                                                             const char* username_from_url, 
                                                             unsigned int allowed_types)> auth_callback);
    void set_remote_certificate_callback(std::function<int(git_cert* cert, bool valid, const char* host)> cert_callback);
    void set_remote_transfer_progress_callback(std::function<int(const git_indexer_progress* stats)> progress_callback);
    void set_remote_sideband_progress_callback(std::function<int(const char* str, int len)> sideband_callback);
    void set_proxy_options(const std::string& url, git_proxy_t proxy_type);
    void set_remote_connect_options(int version = 1);
    std::vector<TransportMessage> get_remote_messages(const std::string& remote_name = "origin");
    void prune_remote_references(const std::string& remote_name = "origin");

    // Submodule Operations
    std::vector<SubmoduleInfo> list_submodules();
    void submodule_init(const std::string& name, bool overwrite = false);
    void submodule_update(const std::string& name, 
                         const std::function<bool(size_t, size_t)>& progress_callback = {});

    // Worktree Operations
    void add_worktree(const std::string& name, const std::string& path, 
                     const std::string& branch = "");
    std::vector<WorktreeInfo> list_worktrees();

    // Advanced Features
    std::vector<BlameHunk> blame_file(const std::string& file_path, 
                                     const std::string& start_commit = "",
                                     const std::string& end_commit = "");
    void add_note(const std::string& commit_id, const std::string& note_namespace,
                  const std::string& message, const Signature& author);
    std::vector<Note> get_notes(const std::string& note_namespace = "refs/notes/commits");

    // Stash Operations
    void stash_save(const Signature& stasher, const std::string& message = "",
                   git_stash_flags flags = GIT_STASH_DEFAULT);
    void stash_pop(size_t index = 0);
    std::vector<std::string> stash_list();

    // Bundle & Archive Operations
    void create_bundle(const std::string& file_path, const std::string& upstream = "origin/master");
    void create_archive(const std::string& file_path, const std::string& treeish = "HEAD",
                       git_archive_format format = GIT_ARCHIVE_FORMAT_TAR);

    // Filtering Operations
    std::string apply_filters(const std::string& content, const std::string& path,
                             git_filter_mode_t filter_mode);

    // Cherry-pick & Revert
    void cherry_pick(const std::string& commit_id);
    void revert(const std::string& commit_id);

    // Utility Methods
    std::string get_current_branch();
    bool is_clean_working_directory();

protected:
    git_repository* repo_ = nullptr;
    mutable std::mutex repo_mutex_;

    void ensure_repository() const;
    void set_repository(git_repository* new_repo);
    void check_error(int error_code) const;

    template<typename T>
    T* lookup_object(const std::string& object_id, git_object_t type);

    git_signature* create_signature(const Signature& sig) const;
    std::string oid_to_string(const git_oid& oid) const;

    void setup_clone_callbacks(git_clone_options& opts, ProgressData& progress_data);
    void setup_fetch_callbacks(git_fetch_options& opts, ProgressData& progress_data);
    void setup_push_callbacks(git_push_options& opts, ProgressData& progress_data,
                             const std::function<bool(size_t, size_t)>& push_progress);
    void setup_refspec_array(git_strarray& array, const std::vector<std::string>& refspecs);
    void setup_diff(git_diff*& diff, const std::string& from_commit, const std::string& to_commit);
    void handle_merge_conflicts(git_index* index, const std::function<bool(const git_merge_file_result*)>& callback);
    bool handle_rebase_conflict(git_rebase* rebase, const std::function<bool(const git_merge_file_result*)>& callback);
};

#endif // GIT_BASE_H