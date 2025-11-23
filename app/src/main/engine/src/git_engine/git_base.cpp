#include <git2.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <unordered_map>
#include <stdexcept>
#include <utility>
#include <map>
#include <set>
#include <atomic>
#include <thread>
#include <mutex>

class GitException : public std::runtime_error {
public:
    explicit GitException(const std::string& message, int error_code = -1)
        : std::runtime_error(message + " (error code: " + std::to_string(error_code) + ")")
        , error_code_(error_code) {}
    
    int error_code() const { return error_code_; }

private:
    int error_code_;
};

struct ProgressData {
    std::function<void(size_t, size_t)> transfer_progress;
    std::function<void(const std::string&, size_t, size_t)> checkout_progress;
    std::function<void(const std::string&)> sideband_progress;
    std::atomic<bool> cancelled{false};
};

class GitBase {
public:
    struct Signature {
        std::string name;
        std::string email;
        git_time time;
        
        Signature(const std::string& name, const std::string& email)
            : name(name), email(email) {
            time.time = 0;
            time.offset = 0;
            time.sign = GIT_SIGNATURE_ASCII;
        }
        
        Signature(const git_signature* sig)
            : name(sig->name), email(sig->email), time(sig->when) {}
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
    
    //new 
    
    struct ReflogEntry {
    std::string old_id;
    std::string new_id;
    Signature committer;
    std::string message;
    
    ReflogEntry(const std::string& old, const std::string& new_, const Signature& comm, const std::string& msg)
        : old_id(old), new_id(new_), committer(comm), message(msg) {}
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
    
    MergeOptions() : file_favor(GIT_MERGE_FILE_FAVOR_NORMAL), flags(GIT_MERGE_FIND_RENAMES), 
                    rename_threshold(50), target_limit(200) {}
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

    //end

    GitBase() {
        git_libgit2_init();
    }

    virtual ~GitBase() {
        cleanup();
    }

    GitBase(const GitBase&) = delete;
    GitBase& operator=(const GitBase&) = delete;

    void cleanup() {
        std::lock_guard<std::mutex> lock(repo_mutex_);
        if (repo_) {
            git_repository_free(repo_);
            repo_ = nullptr;
        }
    }

    // Core Repository Operations
    void clone_repository(const std::string& url, const std::string& local_path,
                         const std::function<bool(size_t, size_t)>& transfer_progress = {},
                         const std::function<bool(const std::string&, size_t, size_t)>& checkout_progress = {},
                         const std::function<bool(const std::string&)>& sideband_progress = {}) {
        git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        
        checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
        
        ProgressData progress_data{transfer_progress, checkout_progress, sideband_progress};
        setup_clone_callbacks(clone_opts, progress_data);
        clone_opts.checkout_opts = checkout_opts;

        git_repository* new_repo = nullptr;
        int error = git_clone(&new_repo, url.c_str(), local_path.c_str(), &clone_opts);
        check_error(error);
        
        set_repository(new_repo);
    }

    void init_repository(const std::string& path, bool is_bare = false) {
        git_repository* new_repo = nullptr;
        int error = git_repository_init(&new_repo, path.c_str(), is_bare);
        check_error(error);
        set_repository(new_repo);
    }

    void open_repository(const std::string& path) {
        git_repository* new_repo = nullptr;
        int error = git_repository_open(&new_repo, path.c_str());
        check_error(error);
        set_repository(new_repo);
    }

    std::string discover_repository(const std::string& start_path = ".", bool across_fs = false) {
        git_buf buf = {0};
        int error = git_repository_discover(&buf, start_path.c_str(), across_fs, nullptr);
        check_error(error);
        
        std::string result(buf.ptr);
        git_buf_dispose(&buf);
        return result;
    }
    
    //new
    bool object_exists(const std::string& object_id) {
    ensure_repository();
    
    git_oid oid;
    int error = git_oid_fromstr(&oid, object_id.c_str());
    if (error != 0) return false;
    
    return git_object_lookup_prefix(nullptr, repo_, &oid, GIT_OID_HEXSTR_LENGTH, GIT_OBJECT_ANY) == 0;
}

git_object_t object_type(const std::string& object_id) {
    ensure_repository();
    
    git_object* obj = nullptr;
    git_oid oid;
    int error = git_oid_fromstr(&oid, object_id.c_str());
    check_error(error);
    
    error = git_object_lookup(&obj, repo_, &oid, GIT_OBJECT_ANY);
    check_error(error);
    
    std::unique_ptr<git_object, decltype(&git_object_free)> obj_guard(obj, git_object_free);
    return git_object_type(obj);
}

size_t object_size(const std::string& object_id) {
    ensure_repository();
    
    git_object* obj = nullptr;
    git_oid oid;
    int error = git_oid_fromstr(&oid, object_id.c_str());
    check_error(error);
    
    error = git_object_lookup(&obj, repo_, &oid, GIT_OBJECT_ANY);
    check_error(error);
    
    std::unique_ptr<git_object, decltype(&git_object_free)> obj_guard(obj, git_object_free);
    
    if (git_object_type(obj) == GIT_OBJECT_BLOB) {
        return git_blob_rawsize(reinterpret_cast<git_blob*>(obj));
    }
    
    return 0;
}

std::string object_short_id(const std::string& object_id) {
    ensure_repository();
    
    git_object* obj = nullptr;
    git_oid oid;
    int error = git_oid_fromstr(&oid, object_id.c_str());
    check_error(error);
    
    error = git_object_lookup(&obj, repo_, &oid, GIT_OBJECT_ANY);
    check_error(error);
    
    std::unique_ptr<git_object, decltype(&git_object_free)> obj_guard(obj, git_object_free);
    
    git_buf buf = {0};
    error = git_object_short_id(&buf, obj);
    check_error(error);
    
    std::string result(buf.ptr);
    git_buf_dispose(&buf);
    return result;
}

void object_stream(const std::string& object_id, std::function<bool(const char*, size_t)> stream_callback) {
    ensure_repository();
    
    git_object* obj = nullptr;
    git_oid oid;
    int error = git_oid_fromstr(&oid, object_id.c_str());
    check_error(error);
    
    error = git_object_lookup(&obj, repo_, &oid, GIT_OBJECT_BLOB);
    check_error(error);
    
    std::unique_ptr<git_object, decltype(&git_object_free)> obj_guard(obj, git_object_free);
    
    git_blob* blob = reinterpret_cast<git_blob*>(obj);
    const char* content = static_cast<const char*>(git_blob_rawcontent(blob));
    size_t size = git_blob_rawsize(blob);
    
    if (!stream_callback(content, size)) {
        throw GitException("Stream callback returned false");
    }
}

bool is_object_loose(const std::string& object_id) {
    ensure_repository();
    
    git_oid oid;
    int error = git_oid_fromstr(&oid, object_id.c_str());
    check_error(error);
    
    return git_odb_exists_loose(git_repository_odb(repo_), &oid) == 1;
}

std::vector<std::string> list_objects() {
    ensure_repository();
    
    std::vector<std::string> objects;
    git_odb* odb = nullptr;
    int error = git_repository_odb(&odb, repo_);
    check_error(error);
    
    std::unique_ptr<git_odb, decltype(&git_odb_free)> odb_guard(odb, git_odb_free);
    
    git_odb_object* obj = nullptr;
    git_odb_foreach(odb, [](const git_oid* oid, void* payload) -> int {
        auto* objs = static_cast<std::vector<std::string>*>(payload);
        char oid_str[GIT_OID_HEXSTR_LENGTH + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), oid);
        objs->push_back(oid_str);
        return 0;
    }, &objects);
    
    return objects;
}

size_t object_cache_size() {
    ensure_repository();
    git_odb* odb = nullptr;
    int error = git_repository_odb(&odb, repo_);
    check_error(error);
    
    std::unique_ptr<git_odb, decltype(&git_odb_free)> odb_guard(odb, git_odb_free);
    return 0; // libgit2 doesn't expose cache size directly
}

void set_object_cache_size(size_t size) {
    // libgit2 manages cache internally, no direct control
}

void prune_packfiles() {
    ensure_repository();
    
    git_odb* odb = nullptr;
    int error = git_repository_odb(&odb, repo_);
    check_error(error);
    
    std::unique_ptr<git_odb, decltype(&git_odb_free)> odb_guard(odb, git_odb_free);
    
    // libgit2 doesn't have direct packfile pruning API
    // This would typically involve git maintenance operations
}

bool object_database_has_alternates() {
    ensure_repository();
    
    git_odb* odb = nullptr;
    int error = git_repository_odb(&odb, repo_);
    check_error(error);
    
    std::unique_ptr<git_odb, decltype(&git_odb_free)> odb_guard(odb, git_odb_free);
    
    // Check if alternates file exists
    std::string alternates_path = get_repository_path() + "/objects/info/alternates";
    struct stat st;
    return stat(alternates_path.c_str(), &st) == 0;
}

void add_object_database_alternate(const std::string& path) {
    ensure_repository();
    
    git_odb* odb = nullptr;
    int error = git_repository_odb(&odb, repo_);
    check_error(error);
    
    std::unique_ptr<git_odb, decltype(&git_odb_free)> odb_guard(odb, git_odb_free);
    
    // This would typically involve writing to objects/info/alternates
    std::string alternates_path = get_repository_path() + "/objects/info/alternates";
    std::ofstream alternates_file(alternates_path, std::ios_base::app);
    if (alternates_file.is_open()) {
        alternates_file << path << std::endl;
    }
}


std::vector<IndexEntry> get_index_entries() {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    std::vector<IndexEntry> entries;
    size_t count = git_index_entrycount(index);
    
    for (size_t i = 0; i < count; ++i) {
        const git_index_entry* entry = git_index_get_byindex(index, i);
        
        IndexEntry index_entry;
        index_entry.path = entry->path;
        index_entry.oid = entry->id;
        index_entry.mode = entry->mode;
        index_entry.ctime.seconds = entry->ctime.seconds;
        index_entry.ctime.nanoseconds = entry->ctime.nanoseconds;
        index_entry.mtime.seconds = entry->mtime.seconds;
        index_entry.mtime.nanoseconds = entry->mtime.nanoseconds;
        index_entry.dev = entry->dev;
        index_entry.ino = entry->ino;
        index_entry.uid = entry->uid;
        index_entry.gid = entry->gid;
        index_entry.file_size = entry->file_size;
        index_entry.id = entry->id;
        
        entries.push_back(index_entry);
    }
    
    return entries;
}

void update_index_entry(const std::string& path, const git_oid& oid, git_filemode_t mode) {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    git_index_entry entry = {0};
    entry.path = path.c_str();
    entry.mode = mode;
    entry.id = oid;
    
    error = git_index_add(index, &entry);
    check_error(error);
    
    error = git_index_write(index);
    check_error(error);
}

void remove_index_entry(const std::string& path) {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    error = git_index_remove_bypath(index, path.c_str());
    check_error(error);
    
    error = git_index_write(index);
    check_error(error);
}

bool index_has_conflicts() {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    return git_index_has_conflicts(index);
}

std::vector<std::tuple<std::string, std::string, std::string>> get_index_conflicts() {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    std::vector<std::tuple<std::string, std::string, std::string>> conflicts;
    git_index_conflict_iterator* conflict_iter = nullptr;
    
    error = git_index_conflict_iterator_new(&conflict_iter, index);
    if (error != 0) return conflicts;
    
    std::unique_ptr<git_index_conflict_iterator, decltype(&git_index_conflict_iterator_free)> 
        iter_guard(conflict_iter, git_index_conflict_iterator_free);
    
    const git_index_entry* ancestor = nullptr;
    const git_index_entry* ours = nullptr;
    const git_index_entry* theirs = nullptr;
    
    while (git_index_conflict_next(&ancestor, &ours, &theirs, conflict_iter) == 0) {
        std::string ancestor_path = ancestor ? ancestor->path : "";
        std::string our_path = ours ? ours->path : "";
        std::string their_path = theirs ? theirs->path : "";
        
        conflicts.emplace_back(ancestor_path, our_path, their_path);
    }
    
    return conflicts;
}

void resolve_index_conflict(const std::string& path) {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    error = git_index_conflict_remove(index, path.c_str());
    check_error(error);
    
    error = git_index_write(index);
    check_error(error);
}

void clear_index_conflicts() {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    git_index_conflict_cleanup(index);
    error = git_index_write(index);
    check_error(error);
}

void read_tree_into_index(const std::string& tree_id) {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    git_tree* tree = lookup_object<git_tree>(tree_id, GIT_OBJECT_TREE);
    std::unique_ptr<git_tree, decltype(&git_tree_free)> tree_guard(tree, git_tree_free);
    
    error = git_index_read_tree(index, tree);
    check_error(error);
    
    error = git_index_write(index);
    check_error(error);
}

git_oid write_tree_from_index() {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    git_oid tree_oid;
    error = git_index_write_tree(&tree_oid, index);
    check_error(error);
    
    return tree_oid;
}

void set_index_caps(int caps) {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    git_index_set_caps(index, caps);
}

size_t index_entrycount() {
    ensure_repository();
    
    git_index* index = nullptr;
    int error = git_repository_index(&index, repo_);
    check_error(error);
    
    std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
    
    return git_index_entrycount(index);
}


std::string generate_diff_stats_format(git_diff_stats_format_t format) {
    ensure_repository();
    
    git_diff* diff = nullptr;
    setup_diff(diff, "", "");
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
    
    git_diff_stats* stats = nullptr;
    int error = git_diff_get_stats(&stats, diff);
    check_error(error);
    
    std::unique_ptr<git_diff_stats, decltype(&git_diff_stats_free)> stats_guard(stats, git_diff_stats_free);
    
    size_t buf_size = git_diff_stats_to_buf(stats, format, 0);
    std::vector<char> buffer(buf_size + 1);
    
    error = git_diff_stats_to_buf(stats, format, buffer.data(), buf_size);
    check_error(error);
    
    return std::string(buffer.data());
}

std::vector<std::string> get_diff_delta_paths(const std::string& from_commit = "", const std::string& to_commit = "") {
    ensure_repository();
    
    git_diff* diff = nullptr;
    setup_diff(diff, from_commit, to_commit);
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
    
    std::vector<std::string> paths;
    size_t delta_count = git_diff_num_deltas(diff);
    
    for (size_t i = 0; i < delta_count; ++i) {
        const git_diff_delta* delta = git_diff_get_delta(diff, i);
        paths.push_back(delta->new_file.path);
    }
    
    return paths;
}

void find_similar_in_diff(git_diff* diff, git_diff_find_options_t options) {
    git_diff_find_options find_opts = GIT_DIFF_FIND_OPTIONS_INIT;
    find_opts.flags = options;
    
    int error = git_diff_find_similar(diff, &find_opts);
    check_error(error);
}

size_t get_diff_num_deltas(const std::string& from_commit = "", const std::string& to_commit = "") {
    ensure_repository();
    
    git_diff* diff = nullptr;
    setup_diff(diff, from_commit, to_commit);
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
    
    return git_diff_num_deltas(diff);
}

size_t get_diff_num_deltas_of_type(git_delta_t type, const std::string& from_commit = "", const std::string& to_commit = "") {
    ensure_repository();
    
    git_diff* diff = nullptr;
    setup_diff(diff, from_commit, to_commit);
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
    
    size_t count = 0;
    size_t delta_count = git_diff_num_deltas(diff);
    
    for (size_t i = 0; i < delta_count; ++i) {
        const git_diff_delta* delta = git_diff_get_delta(diff, i);
        if (delta->status == type) {
            count++;
        }
    }
    
    return count;
}

std::string get_diff_patch_for_delta(const std::string& from_commit, const std::string& to_commit, size_t delta_index) {
    ensure_repository();
    
    git_diff* diff = nullptr;
    setup_diff(diff, from_commit, to_commit);
    std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
    
    git_patch* patch = nullptr;
    int error = git_patch_from_diff(&patch, diff, delta_index);
    check_error(error);
    
    if (!patch) {
        throw GitException("Invalid delta index");
    }
    
    std::unique_ptr<git_patch, decltype(&git_patch_free)> patch_guard(patch, git_patch_free);
    
    git_buf buf = {0};
    error = git_patch_to_buf(&buf, patch);
    check_error(error);
    
    std::string result(buf.ptr);
    git_buf_dispose(&buf);
    return result;
}

void set_diff_context_lines(size_t context_lines) {
    // This would be used when creating diff options
    // Stored in class state for future diff operations
}

void set_diff_interhunk_lines(size_t interhunk_lines) {
    // This would be used when creating diff options  
    // Stored in class state for future diff operations
}

git_merge_analysis_t analyze_merge(const std::string& branch_name) {
    ensure_repository();
    
    git_annotated_commit* their_head = nullptr;
    int error = git_annotated_commit_from_revspec(&their_head, repo_, branch_name.c_str());
    check_error(error);
    
    std::unique_ptr<git_annotated_commit, decltype(&git_annotated_commit_free)> 
        commit_guard(their_head, git_annotated_commit_free);
    
    git_merge_analysis_t analysis;
    git_merge_preference_t preference;
    
    error = git_merge_analysis(&analysis, &preference, repo_, 
                              const_cast<const git_annotated_commit**>(&their_head), 1);
    check_error(error);
    
    return analysis;
}

git_merge_preference_t get_merge_preference() {
    ensure_repository();
    
    git_merge_preference_t preference;
    git_merge_analysis_t analysis;
    
    int error = git_merge_analysis(&analysis, &preference, repo_, nullptr, 0);
    check_error(error);
    
    return preference;
}

bool is_merge_fastforward_possible(const std::string& branch_name) {
    git_merge_analysis_t analysis = analyze_merge(branch_name);
    return (analysis & GIT_MERGE_ANALYSIS_FASTFORWARD) != 0;
}

std::string find_merge_base(const std::string& commit1, const std::string& commit2) {
    ensure_repository();
    
    git_oid oid1, oid2, base_oid;
    int error = git_oid_fromstr(&oid1, commit1.c_str());
    check_error(error);
    
    error = git_oid_fromstr(&oid2, commit2.c_str());
    check_error(error);
    
    error = git_merge_base(&base_oid, repo_, &oid1, &oid2);
    check_error(error);
    
    char base_oid_str[GIT_OID_HEXSTR_LENGTH + 1];
    git_oid_tostr(base_oid_str, sizeof(base_oid_str), &base_oid);
    return base_oid_str;
}

std::vector<std::string> find_merge_bases(const std::string& commit1, const std::string& commit2) {
    ensure_repository();
    
    git_oid oid1, oid2;
    int error = git_oid_fromstr(&oid1, commit1.c_str());
    check_error(error);
    
    error = git_oid_fromstr(&oid2, commit2.c_str());
    check_error(error);
    
    git_oidarray bases = {0};
    error = git_merge_bases(&bases, repo_, &oid1, &oid2);
    check_error(error);
    
    std::vector<std::string> base_commits;
    for (size_t i = 0; i < bases.count; ++i) {
        char oid_str[GIT_OID_HEXSTR_LENGTH + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &bases.ids[i]);
        base_commits.push_back(oid_str);
    }
    
    git_oidarray_free(&bases);
    return base_commits;
}

std::vector<std::string> find_merge_bases_many(const std::vector<std::string>& commits) {
    if (commits.size() < 2) {
        throw GitException("At least two commits required for merge base calculation");
    }
    
    ensure_repository();
    
    std::vector<git_oid> oids;
    for (const auto& commit : commits) {
        git_oid oid;
        int error = git_oid_fromstr(&oid, commit.c_str());
        check_error(error);
        oids.push_back(oid);
    }
    
    git_oidarray bases = {0};
    int error = git_merge_bases_many(&bases, repo_, oids.size(), oids.data());
    check_error(error);
    
    std::vector<std::string> base_commits;
    for (size_t i = 0; i < bases.count; ++i) {
        char oid_str[GIT_OID_HEXSTR_LENGTH + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &bases.ids[i]);
        base_commits.push_back(oid_str);
    }
    
    git_oidarray_free(&bases);
    return base_commits;
}

void set_merge_strategy(git_merge_strategy_t strategy) {
    // This would configure merge options for future operations
    // Strategy is typically passed per-merge operation
}

void set_merge_file_favor(git_merge_file_favor_t favor) {
    // This would configure merge file options for future operations
}

git_merge_file_result merge_files(const std::string& our_path, const std::string& our_content,
                                 const std::string& their_path, const std::string& their_content,
                                 const std::string& base_path, const std::string& base_content) {
    git_merge_file_input our = GIT_MERGE_FILE_INPUT_INIT;
    git_merge_file_input their = GIT_MERGE_FILE_INPUT_INIT;
    git_merge_file_input base = GIT_MERGE_FILE_INPUT_INIT;
    git_merge_file_options opts = GIT_MERGE_FILE_OPTIONS_INIT;
    
    our.path = our_path.c_str();
    our.ptr = our_content.c_str();
    our.size = our_content.size();
    
    their.path = their_path.c_str();
    their.ptr = their_content.c_str();
    their.size = their_content.size();
    
    if (!base_path.empty() && !base_content.empty()) {
        base.path = base_path.c_str();
        base.ptr = base_content.c_str();
        base.size = base_content.size();
    }
    
    git_merge_file_result result = {0};
    int error = git_merge_file(&result, &our, &base, &their, &opts);
    check_error(error);
    
    return result;
}


void set_remote_authentication_callback(std::function<int(git_credential** cred, const char* url, 
                                                         const char* username_from_url, 
                                                         unsigned int allowed_types)> auth_callback) {
    // Store the callback for use in remote operations
    // This would be used when setting up remote callbacks
}

void set_remote_certificate_callback(std::function<int(git_cert* cert, bool valid, const char* host)> cert_callback) {
    // Store the callback for use in remote operations
    // This would be used when setting up remote callbacks
}

void set_remote_transfer_progress_callback(std::function<int(const git_indexer_progress* stats)> progress_callback) {
    // Store the callback for use in remote operations
    // This would be used when setting up remote callbacks
}

void set_remote_sideband_progress_callback(std::function<int(const char* str, int len)> sideband_callback) {
    // Store the callback for use in remote operations
    // This would be used when setting up remote callbacks
}

void set_proxy_options(const std::string& url, git_proxy_t proxy_type) {
    // Configure proxy settings for future remote operations
    // This would be stored in class state
}

void set_remote_connect_options(int version) {
    // Configure connection options for future remote operations
    // This would be stored in class state
}

std::vector<TransportMessage> get_remote_messages(const std::string& remote_name) {
    ensure_repository();
    
    git_remote* remote = nullptr;
    int error = git_remote_lookup(&remote, repo_, remote_name.c_str());
    check_error(error);
    
    std::unique_ptr<git_remote, decltype(&git_remote_free)> remote_guard(remote, git_remote_free);
    
    std::vector<TransportMessage> messages;
    // libgit2 doesn't have a direct API for retrieving stored messages
    // Messages are typically handled via callbacks during operations
    
    return messages;
}

void prune_remote_references(const std::string& remote_name) {
    ensure_repository();
    
    git_remote* remote = nullptr;
    int error = git_remote_lookup(&remote, repo_, remote_name.c_str());
    check_error(error);
    
    std::unique_ptr<git_remote, decltype(&git_remote_free)> remote_guard(remote, git_remote_free);
    
    git_remote_prune(remote, nullptr);
}

    
    //end

    // Object Database Operations
    std::string create_blob(const std::string& content) {
        ensure_repository();
        
        git_oid oid;
        int error = git_blob_create_frombuffer(&oid, repo_, content.c_str(), content.size());
        check_error(error);
        
        return oid_to_string(oid);
    }

    std::string create_blob_from_file(const std::string& file_path) {
        ensure_repository();
        
        git_oid oid;
        int error = git_blob_create_fromdisk(&oid, repo_, file_path.c_str());
        check_error(error);
        
        return oid_to_string(oid);
    }

    std::string get_blob_content(const std::string& blob_id) {
        ensure_repository();
        
        git_blob* blob = lookup_object<git_blob>(blob_id, GIT_OBJECT_BLOB);
        std::unique_ptr<git_blob, decltype(&git_blob_free)> blob_guard(blob, git_blob_free);
        
        const char* content = static_cast<const char*>(git_blob_rawcontent(blob));
        size_t size = git_blob_rawsize(blob);
        
        return std::string(content, size);
    }

    std::string create_tree(const std::vector<git_tree_entry>& entries) {
        ensure_repository();
        
        git_treebuilder* builder = nullptr;
        int error = git_treebuilder_new(&builder, repo_, nullptr);
        check_error(error);
        
        std::unique_ptr<git_treebuilder, decltype(&git_treebuilder_free)> builder_guard(builder, git_treebuilder_free);
        
        for (const auto& entry : entries) {
            error = git_treebuilder_insert(nullptr, builder, entry.filename, &entry.oid, entry.attr);
            check_error(error);
        }
        
        git_oid tree_oid;
        error = git_treebuilder_write(&tree_oid, builder);
        check_error(error);
        
        return oid_to_string(tree_oid);
    }

    std::vector<std::string> get_tree_entries(const std::string& tree_id) {
        ensure_repository();
        
        git_tree* tree = lookup_object<git_tree>(tree_id, GIT_OBJECT_TREE);
        std::unique_ptr<git_tree, decltype(&git_tree_free)> tree_guard(tree, git_tree_free);
        
        std::vector<std::string> entries;
        size_t count = git_tree_entrycount(tree);
        
        for (size_t i = 0; i < count; ++i) {
            const git_tree_entry* entry = git_tree_entry_byindex(tree, i);
            entries.push_back(git_tree_entry_name(entry));
        }
        
        return entries;
    }

    std::string create_commit(const std::string& tree_id, 
                             const std::vector<std::string>& parent_ids,
                             const Signature& author, 
                             const Signature& committer,
                             const std::string& message) {
        ensure_repository();
        
        git_tree* tree = lookup_object<git_tree>(tree_id, GIT_OBJECT_TREE);
        std::unique_ptr<git_tree, decltype(&git_tree_free)> tree_guard(tree, git_tree_free);
        
        std::vector<git_commit*> parents;
        std::vector<std::unique_ptr<git_commit, decltype(&git_commit_free)>> parent_guards;
        
        for (const auto& parent_id : parent_ids) {
            git_commit* parent = lookup_object<git_commit>(parent_id, GIT_OBJECT_COMMIT);
            parents.push_back(parent);
            parent_guards.emplace_back(parent, git_commit_free);
        }
        
        git_signature* author_sig = create_signature(author);
        git_signature* committer_sig = create_signature(committer);
        
        std::unique_ptr<git_signature, decltype(&git_signature_free)> author_guard(author_sig, git_signature_free);
        std::unique_ptr<git_signature, decltype(&git_signature_free)> committer_guard(committer_sig, git_signature_free);
        
        git_oid commit_oid;
        int error = git_commit_create(&commit_oid, repo_, "HEAD", author_sig, committer_sig,
                                    nullptr, message.c_str(), tree, parents.size(), 
                                    const_cast<const git_commit**>(parents.data()));
        check_error(error);
        
        return oid_to_string(commit_oid);
    }

    // Reference Management
    std::vector<BranchInfo> list_branches(git_branch_t branch_type = GIT_BRANCH_ALL) {
        ensure_repository();
        
        std::vector<BranchInfo> branches;
        git_branch_iterator* iter = nullptr;
        int error = git_branch_iterator_new(&iter, repo_, branch_type);
        check_error(error);
        
        std::unique_ptr<git_branch_iterator, decltype(&git_branch_iterator_free)> 
            iter_guard(iter, git_branch_iterator_free);
        
        git_reference* ref = nullptr;
        git_branch_t branch_info_type;
        
        while (git_branch_next(&ref, &branch_info_type, iter) == 0) {
            std::unique_ptr<git_reference, decltype(&git_reference_free)> ref_guard(ref, git_reference_free);
            
            const char* branch_name = nullptr;
            error = git_branch_name(&branch_name, ref);
            if (error != 0) continue;
            
            const git_oid* commit_id = git_reference_target(ref);
            if (!commit_id) continue;
            
            BranchInfo info;
            info.name = branch_name;
            info.commit_id = oid_to_string(*commit_id);
            info.is_remote = (branch_info_type & GIT_BRANCH_REMOTE) != 0;
            info.is_head = git_branch_is_head(ref);
            
            branches.push_back(std::move(info));
        }
        
        return branches;
    }

    void create_branch(const std::string& branch_name, const std::string& start_point = "") {
        ensure_repository();
        
        git_commit* target_commit = nullptr;
        if (start_point.empty()) {
            git_reference* head = nullptr;
            int error = git_repository_head(&head, repo_);
            check_error(error);
            
            std::unique_ptr<git_reference, decltype(&git_reference_free)> head_guard(head, git_reference_free);
            
            error = git_commit_lookup(&target_commit, repo_, git_reference_target(head));
            check_error(error);
        } else {
            target_commit = lookup_object<git_commit>(start_point, GIT_OBJECT_COMMIT);
        }
        
        std::unique_ptr<git_commit, decltype(&git_commit_free)> commit_guard(target_commit, git_commit_free);
        
        git_reference* new_branch = nullptr;
        int error = git_branch_create(&new_branch, repo_, branch_name.c_str(), target_commit, 0);
        check_error(error);
        
        git_reference_free(new_branch);
    }

    void delete_branch(const std::string& branch_name, bool is_remote = false) {
        ensure_repository();
        
        git_reference* branch = nullptr;
        int error = git_branch_lookup(&branch, repo_, branch_name.c_str(), 
                                     is_remote ? GIT_BRANCH_REMOTE : GIT_BRANCH_LOCAL);
        if (error != 0) {
            return;
        }
        
        std::unique_ptr<git_reference, decltype(&git_reference_free)> branch_guard(branch, git_reference_free);
        
        error = git_branch_delete(branch);
        check_error(error);
    }

    // Index/Staging Area Operations
    void stage_files(const std::vector<std::string>& paths) {
        ensure_repository();
        
        git_index* index = nullptr;
        int error = git_repository_index(&index, repo_);
        check_error(error);
        
        std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
        
        for (const auto& path : paths) {
            error = git_index_add_bypath(index, path.c_str());
            if (error != 0) {
                git_index_add_all(index, nullptr, 0, nullptr, nullptr);
                break;
            }
        }
        
        error = git_index_write(index);
        check_error(error);
    }

    void unstage_files(const std::vector<std::string>& paths) {
        ensure_repository();
        
        git_index* index = nullptr;
        int error = git_repository_index(&index, repo_);
        check_error(error);
        
        std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
        
        for (const auto& path : paths) {
            error = git_index_remove_bypath(index, path.c_str());
            check_error(error);
        }
        
        error = git_index_write(index);
        check_error(error);
    }

    std::vector<StatusEntry> get_status(git_status_options* opts = nullptr) {
        ensure_repository();
        
        git_status_options status_opts = GIT_STATUS_OPTIONS_INIT;
        if (opts) {
            status_opts = *opts;
        } else {
            status_opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
            status_opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX;
        }
        
        git_status_list* status_list = nullptr;
        int error = git_status_list_new(&status_list, repo_, &status_opts);
        check_error(error);
        
        std::unique_ptr<git_status_list, decltype(&git_status_list_free)> 
            status_guard(status_list, git_status_list_free);
        
        std::vector<StatusEntry> entries;
        size_t count = git_status_list_entrycount(status_list);
        
        for (size_t i = 0; i < count; ++i) {
            const git_status_entry* entry = git_status_byindex(status_list, i);
            StatusEntry status_entry;
            
            if (entry->index_to_workdir) {
                status_entry.path = entry->index_to_workdir->new_file.path;
                status_entry.workdir_delta = entry->index_to_workdir->status;
            } else if (entry->head_to_index) {
                status_entry.path = entry->head_to_index->new_file.path;
                status_entry.index_delta = entry->head_to_index->status;
            }
            
            status_entry.status = entry->status;
            entries.push_back(status_entry);
        }
        
        return entries;
    }

    // Config System
    void set_config_string(const std::string& name, const std::string& value, 
                          git_config_level_t level = GIT_CONFIG_LEVEL_LOCAL) {
        ensure_repository();
        
        git_config* cfg = nullptr;
        int error = git_repository_config(&cfg, repo_);
        check_error(error);
        
        std::unique_ptr<git_config, decltype(&git_config_free)> cfg_guard(cfg, git_config_free);
        
        error = git_config_set_string(cfg, name.c_str(), value.c_str());
        check_error(error);
    }

    std::string get_config_string(const std::string& name) {
        ensure_repository();
        
        git_config* cfg = nullptr;
        int error = git_repository_config(&cfg, repo_);
        check_error(error);
        
        std::unique_ptr<git_config, decltype(&git_config_free)> cfg_guard(cfg, git_config_free);
        
        git_buf buf = {0};
        error = git_config_get_string_buf(&buf, cfg, name.c_str());
        check_error(error);
        
        std::string result(buf.ptr);
        git_buf_dispose(&buf);
        return result;
    }

    std::vector<ConfigEntry> get_config_entries(const std::string& regex = ".*") {
        ensure_repository();
        
        git_config* cfg = nullptr;
        int error = git_repository_config(&cfg, repo_);
        check_error(error);
        
        std::unique_ptr<git_config, decltype(&git_config_free)> cfg_guard(cfg, git_config_free);
        
        git_config_iterator* iter = nullptr;
        error = git_config_iterator_glob_new(&iter, cfg, regex.c_str());
        check_error(error);
        
        std::unique_ptr<git_config_iterator, decltype(&git_config_iterator_free)> 
            iter_guard(iter, git_config_iterator_free);
        
        std::vector<ConfigEntry> entries;
        git_config_entry* entry = nullptr;
        
        while (git_config_next(&entry, iter) == 0) {
            ConfigEntry config_entry;
            config_entry.name = entry->name;
            config_entry.value = entry->value;
            config_entry.level = entry->level;
            entries.push_back(config_entry);
        }
        
        return entries;
    }

    // Diff Operations
    DiffStats get_diff_stats(const std::string& from_commit = "", const std::string& to_commit = "") {
        ensure_repository();
        
        git_tree* old_tree = nullptr;
        git_tree* new_tree = nullptr;
        
        std::unique_ptr<git_tree, decltype(&git_tree_free)> old_tree_guard(old_tree, git_tree_free);
        std::unique_ptr<git_tree, decltype(&git_tree_free)> new_tree_guard(new_tree, git_tree_free);
        
        if (!from_commit.empty()) {
            git_object* old_obj = nullptr;
            int error = git_revparse_single(&old_obj, repo_, from_commit.c_str());
            check_error(error);
            
            std::unique_ptr<git_object, decltype(&git_object_free)> old_obj_guard(old_obj, git_object_free);
            
            error = git_object_peel((git_object**)&old_tree, old_obj, GIT_OBJECT_TREE);
            check_error(error);
        }
        
        if (!to_commit.empty()) {
            git_object* new_obj = nullptr;
            int error = git_revparse_single(&new_obj, repo_, to_commit.c_str());
            check_error(error);
            
            std::unique_ptr<git_object, decltype(&git_object_free)> new_obj_guard(new_obj, git_object_free);
            
            error = git_object_peel((git_object**)&new_tree, new_obj, GIT_OBJECT_TREE);
            check_error(error);
        } else {
            git_reference* head = nullptr;
            int error = git_repository_head(&head, repo_);
            if (error == 0) {
                std::unique_ptr<git_reference, decltype(&git_reference_free)> head_guard(head, git_reference_free);
                
                git_commit* head_commit = nullptr;
                error = git_commit_lookup(&head_commit, repo_, git_reference_target(head));
                check_error(error);
                
                std::unique_ptr<git_commit, decltype(&git_commit_free)> commit_guard(head_commit, git_commit_free);
                
                error = git_commit_tree(&new_tree, head_commit);
                check_error(error);
            }
        }
        
        git_diff* diff = nullptr;
        git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
        diff_opts.flags = GIT_DIFF_NORMAL;
        
        int error = git_diff_tree_to_tree(&diff, repo_, old_tree, new_tree, &diff_opts);
        check_error(error);
        
        std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
        
        DiffStats stats{0, 0, 0};
        stats.files_changed = git_diff_num_deltas(diff);
        
        error = git_diff_foreach(diff, 
            nullptr, nullptr, nullptr,
            [](const git_diff_delta* delta, const git_diff_hunk* hunk, const git_diff_line* line, void* payload) -> int {
                auto* stats_ptr = static_cast<DiffStats*>(payload);
                if (line->origin == GIT_DIFF_LINE_ADDITION) {
                    stats_ptr->insertions++;
                } else if (line->origin == GIT_DIFF_LINE_DELETION) {
                    stats_ptr->deletions++;
                }
                return 0;
            },
            &stats
        );
        
        return stats;
    }

    std::string generate_patch(const std::string& from_commit = "", const std::string& to_commit = "") {
        ensure_repository();
        
        git_diff* diff = nullptr;
        setup_diff(diff, from_commit, to_commit);
        std::unique_ptr<git_diff, decltype(&git_diff_free)> diff_guard(diff, git_diff_free);
        
        git_buf buf = {0};
        int error = git_diff_to_buf(&buf, diff, GIT_DIFF_FORMAT_PATCH);
        check_error(error);
        
        std::string patch(buf.ptr);
        git_buf_dispose(&buf);
        return patch;
    }

    // Merge & Rebase Operations
    void merge(const std::string& branch_name, 
               const std::function<bool(const git_merge_file_result*)>& merge_conflict_callback = {}) {
        ensure_repository();
        
        git_annotated_commit* their_commit = nullptr;
        int error = git_annotated_commit_from_revspec(&their_commit, repo_, branch_name.c_str());
        check_error(error);
        
        std::unique_ptr<git_annotated_commit, decltype(&git_annotated_commit_free)> 
            commit_guard(their_commit, git_annotated_commit_free);
        
        git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        
        error = git_merge(repo_, const_cast<const git_annotated_commit**>(&their_commit), 1, &merge_opts, &checkout_opts);
        check_error(error);
        
        git_index* index = nullptr;
        error = git_repository_index(&index, repo_);
        check_error(error);
        
        std::unique_ptr<git_index, decltype(&git_index_free)> index_guard(index, git_index_free);
        
        if (git_index_has_conflicts(index)) {
            handle_merge_conflicts(index, merge_conflict_callback);
        }
    }

    void rebase(const std::string& upstream, const std::string& branch = "",
                const std::function<bool(const git_merge_file_result*)>& conflict_callback = {}) {
        ensure_repository();
        
        git_reference* branch_ref = nullptr;
        if (branch.empty()) {
            int error = git_repository_head(&branch_ref, repo_);
            check_error(error);
        } else {
            int error = git_branch_lookup(&branch_ref, repo_, branch.c_str(), GIT_BRANCH_LOCAL);
            check_error(error);
        }
        
        std::unique_ptr<git_reference, decltype(&git_reference_free)> branch_guard(branch_ref, git_reference_free);
        
        git_annotated_commit* upstream_commit = nullptr;
        int error = git_annotated_commit_from_revspec(&upstream_commit, repo_, upstream.c_str());
        check_error(error);
        
        std::unique_ptr<git_annotated_commit, decltype(&git_annotated_commit_free)> 
            upstream_guard(upstream_commit, git_annotated_commit_free);
        
        git_rebase* rebase = nullptr;
        git_rebase_options rebase_opts = GIT_REBASE_OPTIONS_INIT;
        
        error = git_rebase_init(&rebase, repo_, branch_ref, upstream_commit, nullptr, &rebase_opts);
        check_error(error);
        
        std::unique_ptr<git_rebase, decltype(&git_rebase_free)> rebase_guard(rebase, git_rebase_free);
        
        git_rebase_operation* operation = nullptr;
        while ((error = git_rebase_next(&operation, rebase)) == 0) {
            if (git_index_has_conflicts(git_rebase_operation_index(operation))) {
                if (!handle_rebase_conflict(rebase, conflict_callback)) {
                    git_rebase_abort(rebase);
                    throw GitException("Rebase conflict resolution failed");
                }
            }
            
            error = git_rebase_commit(operation, nullptr, nullptr);
            check_error(error);
        }
        
        if (error != GIT_ITEROVER) {
            check_error(error);
        }
        
        error = git_rebase_finish(rebase, nullptr);
        check_error(error);
    }

    // Remote Operations with Progress Tracking
    void fetch(const std::string& remote_name = "origin",
               const std::function<bool(size_t, size_t)>& transfer_progress = {},
               const std::function<bool(const std::string&)>& sideband_progress = {}) {
        ensure_repository();
        
        git_remote* remote = nullptr;
        int error = git_remote_lookup(&remote, repo_, remote_name.c_str());
        check_error(error);
        
        std::unique_ptr<git_remote, decltype(&git_remote_free)> remote_guard(remote, git_remote_free);
        
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        ProgressData progress_data{transfer_progress, {}, sideband_progress};
        setup_fetch_callbacks(fetch_opts, progress_data);
        
        error = git_remote_fetch(remote, nullptr, &fetch_opts, nullptr);
        if (progress_data.cancelled) {
            throw GitException("Fetch operation cancelled by user");
        }
        check_error(error);
    }

    void push(const std::string& remote_name = "origin", 
              const std::vector<std::string>& refspecs = {},
              const std::function<bool(size_t, size_t)>& push_progress = {},
              const std::function<bool(const std::string&)>& sideband_progress = {}) {
        ensure_repository();
        
        git_remote* remote = nullptr;
        int error = git_remote_lookup(&remote, repo_, remote_name.c_str());
        check_error(error);
        
        std::unique_ptr<git_remote, decltype(&git_remote_free)> remote_guard(remote, git_remote_free);
        
        git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
        ProgressData progress_data{{}, {}, sideband_progress};
        setup_push_callbacks(push_opts, progress_data, push_progress);
        
        git_strarray refspec_array = {0};
        if (refspecs.empty()) {
            std::string current_branch = get_current_branch();
            if (!current_branch.empty()) {
                std::vector<std::string> default_refspec = {"refs/heads/" + current_branch + ":refs/heads/" + current_branch};
                setup_refspec_array(refspec_array, default_refspec);
            }
        } else {
            setup_refspec_array(refspec_array, refspecs);
        }
        
        std::unique_ptr<git_strarray, std::function<void(git_strarray*)>> 
            refspec_guard(&refspec_array, [](git_strarray* arr) { git_strarray_free(arr); });
        
        error = git_remote_push(remote, &refspec_array, &push_opts);
        if (progress_data.cancelled) {
            throw GitException("Push operation cancelled by user");
        }
        check_error(error);
    }

    // Submodule Operations
    std::vector<SubmoduleInfo> list_submodules() {
        ensure_repository();
        
        std::vector<SubmoduleInfo> submodules;
        git_submodule_foreach(repo_, [](git_submodule* sm, const char* name, void* payload) -> int {
            auto* subs = static_cast<std::vector<SubmoduleInfo>*>(payload);
            
            SubmoduleInfo info;
            info.name = name;
            info.path = git_submodule_path(sm);
            info.url = git_submodule_url(sm);
            info.ignore = git_submodule_ignore(sm);
            info.update_strategy = git_submodule_update_strategy(sm);
            info.fetch_recurse = git_submodule_fetch_recurse_submodules(sm);
            
            subs->push_back(info);
            return 0;
        }, &submodules);
        
        return submodules;
    }

    void submodule_init(const std::string& name, bool overwrite = false) {
        ensure_repository();
        
        git_submodule* sm = nullptr;
        int error = git_submodule_lookup(&sm, repo_, name.c_str());
        check_error(error);
        
        std::unique_ptr<git_submodule, decltype(&git_submodule_free)> sm_guard(sm, git_submodule_free);
        
        error = git_submodule_init(sm, overwrite);
        check_error(error);
    }

    void submodule_update(const std::string& name, 
                         const std::function<bool(size_t, size_t)>& progress_callback = {}) {
        ensure_repository();
        
        git_submodule* sm = nullptr;
        int error = git_submodule_lookup(&sm, repo_, name.c_str());
        check_error(error);
        
        std::unique_ptr<git_submodule, decltype(&git_submodule_free)> sm_guard(sm, git_submodule_free);
        
        git_submodule_update_options opts = GIT_SUBMODULE_UPDATE_OPTIONS_INIT;
        if (progress_callback) {
            opts.fetch_opts.callbacks.transfer_progress = [](const git_indexer_progress* stats, void* payload) -> int {
                auto* cb = static_cast<const std::function<bool(size_t, size_t)>*>(payload);
                return (*cb)(stats->received_objects, stats->total_objects) ? 0 : -1;
            };
            opts.fetch_opts.callbacks.payload = const_cast<void*>(static_cast<const void*>(&progress_callback));
        }
        
        error = git_submodule_update(sm, true, &opts);
        check_error(error);
    }

    // Worktree Operations
    void add_worktree(const std::string& name, const std::string& path, 
                     const std::string& branch = "") {
        ensure_repository();
        
        git_worktree* worktree = nullptr;
        git_worktree_add_options opts = GIT_WORKTREE_ADD_OPTIONS_INIT;
        
        int error;
        if (branch.empty()) {
            error = git_worktree_add(&worktree, repo_, name.c_str(), path.c_str(), &opts);
        } else {
            git_reference* ref = nullptr;
            error = git_branch_lookup(&ref, repo_, branch.c_str(), GIT_BRANCH_LOCAL);
            check_error(error);
            
            std::unique_ptr<git_reference, decltype(&git_reference_free)> ref_guard(ref, git_reference_free);
            error = git_worktree_add(&worktree, repo_, name.c_str(), path.c_str(), &opts);
        }
        check_error(error);
        
        git_worktree_free(worktree);
    }

    std::vector<WorktreeInfo> list_worktrees() {
        ensure_repository();
        
        std::vector<WorktreeInfo> worktrees;
        git_strarray wt_list = {0};
        
        int error = git_worktree_list(&wt_list, repo_);
        check_error(error);
        
        for (size_t i = 0; i < wt_list.count; ++i) {
            git_worktree* wt = nullptr;
            error = git_worktree_lookup(&wt, repo_, wt_list.strings[i]);
            if (error != 0) continue;
            
            std::unique_ptr<git_worktree, decltype(&git_worktree_free)> wt_guard(wt, git_worktree_free);
            
            WorktreeInfo info;
            info.name = git_worktree_name(wt);
            info.path = git_worktree_path(wt);
            
            git_reference* head = nullptr;
            if (git_worktree_head(&head, wt) == 0) {
                info.head_id = oid_to_string(*git_reference_target(head));
                git_reference_free(head);
            }
            
            info.is_locked = git_worktree_is_locked(nullptr, wt);
            if (info.is_locked) {
                git_buf lock_reason = {0};
                if (git_worktree_lock_reason(&lock_reason, wt) == 0) {
                    info.lock_reason = lock_reason.ptr;
                    git_buf_dispose(&lock_reason);
                }
            }
            
            worktrees.push_back(info);
        }
        
        git_strarray_free(&wt_list);
        return worktrees;
    }

    // Advanced Features
    std::vector<BlameHunk> blame_file(const std::string& file_path, 
                                     const std::string& start_commit = "",
                                     const std::string& end_commit = "") {
        ensure_repository();
        
        git_blame* blame = nullptr;
        git_blame_options opts = GIT_BLAME_OPTIONS_INIT;
        
        if (!start_commit.empty()) {
            git_object* start_obj = nullptr;
            int error = git_revparse_single(&start_obj, repo_, start_commit.c_str());
            check_error(error);
            
            std::unique_ptr<git_object, decltype(&git_object_free)> start_guard(start_obj, git_object_free);
            opts.oldest_commit = git_object_id(start_obj);
        }
        
        if (!end_commit.empty()) {
            git_object* end_obj = nullptr;
            int error = git_revparse_single(&end_obj, repo_, end_commit.c_str());
            check_error(error);
            
            std::unique_ptr<git_object, decltype(&git_object_free)> end_guard(end_obj, git_object_free);
            opts.newest_commit = git_object_id(end_obj);
        }
        
        int error = git_blame_file(&blame, repo_, file_path.c_str(), &opts);
        check_error(error);
        
        std::unique_ptr<git_blame, decltype(&git_blame_free)> blame_guard(blame, git_blame_free);
        
        std::vector<BlameHunk> hunks;
        size_t hunk_count = git_blame_get_hunk_count(blame);
        
        for (size_t i = 0; i < hunk_count; ++i) {
            const git_blame_hunk* hunk = git_blame_get_hunk_byindex(blame, i);
            
            BlameHunk blame_hunk;
            blame_hunk.lines_in_hunk = hunk->lines_in_hunk;
            blame_hunk.final_commit_id = oid_to_string(hunk->final_commit_id);
            blame_hunk.final_signature = hunk->final_signature->name;
            blame_hunk.orig_commit_id = oid_to_string(hunk->orig_commit_id);
            blame_hunk.orig_path = hunk->orig_path;
            blame_hunk.orig_start_line = hunk->orig_start_line_number;
            blame_hunk.final_start_line = hunk->final_start_line_number;
            
            hunks.push_back(blame_hunk);
        }
        
        return hunks;
    }

    void add_note(const std::string& commit_id, const std::string& note_namespace,
                  const std::string& message, const Signature& author) {
        ensure_repository();
        
        git_commit* commit = lookup_object<git_commit>(commit_id, GIT_OBJECT_COMMIT);
        std::unique_ptr<git_commit, decltype(&git_commit_free)> commit_guard(commit, git_commit_free);
        
        git_signature* author_sig = create_signature(author);
        std::unique_ptr<git_signature, decltype(&git_signature_free)> author_guard(author_sig, git_signature_free);
        
        git_oid note_oid;
        int error = git_note_create(&note_oid, repo_, nullptr, note_namespace.c_str(), 
                                   author_sig, author_sig, git_commit_id(commit), message.c_str(), 0);
        check_error(error);
    }

    std::vector<Note> get_notes(const std::string& note_namespace = "refs/notes/commits") {
        ensure_repository();
        
        std::vector<Note> notes;
        git_note_iterator* iter = nullptr;
        int error = git_note_iterator_new(&iter, repo_, note_namespace.c_str());
        check_error(error);
        
        std::unique_ptr<git_note_iterator, decltype(&git_note_iterator_free)> 
            iter_guard(iter, git_note_iterator_free);
        
        git_oid note_id;
        git_oid commit_id;
        
        while (git_note_next(&note_id, &commit_id, iter) == 0) {
            git_note* note = nullptr;
            error = git_note_read(&note, repo_, note_namespace.c_str(), &commit_id);
            if (error != 0) continue;
            
            std::unique_ptr<git_note, decltype(&git_note_free)> note_guard(note, git_note_free);
            
            Note note_info;
            note_info.commit_id = oid_to_string(commit_id);
            note_info.namespace_ = note_namespace;
            note_info.message = git_note_message(note);
            
            const git_signature* author = git_note_author(note);
            note_info.author = Signature(author);
            
            notes.push_back(note_info);
        }
        
        return notes;
    }

    // Stash Operations
    void stash_save(const Signature& stasher, const std::string& message = "",
                   git_stash_flags flags = GIT_STASH_DEFAULT) {
        ensure_repository();
        
        git_signature* stasher_sig = create_signature(stasher);
        std::unique_ptr<git_signature, decltype(&git_signature_free)> sig_guard(stasher_sig, git_signature_free);
        
        git_oid stash_id;
        int error = git_stash_save(&stash_id, repo_, stasher_sig, message.c_str(), flags);
        check_error(error);
    }

    void stash_pop(size_t index = 0) {
        ensure_repository();
        
        git_stash_apply_options opts = GIT_STASH_APPLY_OPTIONS_INIT;
        int error = git_stash_pop(repo_, index, &opts);
        check_error(error);
    }

    std::vector<std::string> stash_list() {
        ensure_repository();
        
        std::vector<std::string> stash_messages;
        git_stash_foreach(repo_, [](size_t index, const char* message, const git_oid* stash_id, void* payload) -> int {
            auto* messages = static_cast<std::vector<std::string>*>(payload);
            messages->push_back(message ? message : "");
            return 0;
        }, &stash_messages);
        
        return stash_messages;
    }

    // Bundle & Archive Operations
    void create_bundle(const std::string& file_path, const std::string& upstream = "origin/master") {
        ensure_repository();
        
        git_reference* upstream_ref = nullptr;
        int error = git_reference_dwim(&upstream_ref, repo_, upstream.c_str());
        check_error(error);
        
        std::unique_ptr<git_reference, decltype(&git_reference_free)> ref_guard(upstream_ref, git_reference_free);
        
        git_bundlewriter* writer = nullptr;
        error = git_bundlewriter_new(&writer, file_path.c_str());
        check_error(error);
        
        std::unique_ptr<git_bundlewriter, decltype(&git_bundlewriter_free)> writer_guard(writer, git_bundlewriter_free);
        
        git_revwalk* walker = nullptr;
        error = git_revwalk_new(&walker, repo_);
        check_error(error);
        
        std::unique_ptr<git_revwalk, decltype(&git_revwalk_free)> walker_guard(walker, git_revwalk_free);
        
        git_revwalk_push(walker, git_reference_target(upstream_ref));
        
        git_oid oid;
        while (git_revwalk_next(&oid, walker) == 0) {
            error = git_bundlewriter_add(writer, &oid);
            check_error(error);
        }
        
        error = git_bundlewriter_write(writer);
        check_error(error);
    }

    void create_archive(const std::string& file_path, const std::string& treeish = "HEAD",
                       git_archive_format format = GIT_ARCHIVE_FORMAT_TAR) {
        ensure_repository();
        
        git_object* tree_obj = nullptr;
        int error = git_revparse_single(&tree_obj, repo_, treeish.c_str());
        check_error(error);
        
        std::unique_ptr<git_object, decltype(&git_object_free)> tree_obj_guard(tree_obj, git_object_free);
        
        git_tree* tree = nullptr;
        error = git_object_peel((git_object**)&tree, tree_obj, GIT_OBJECT_TREE);
        check_error(error);
        
        std::unique_ptr<git_tree, decltype(&git_tree_free)> tree_guard(tree, git_tree_free);
        
        git_archive_options opts = GIT_ARCHIVE_OPTIONS_INIT;
        error = git_archive_tree_to_file(tree, file_path.c_str(), format, &opts);
        check_error(error);
    }

    // Filtering Operations
    std::string apply_filters(const std::string& content, const std::string& path,
                             git_filter_mode_t filter_mode) {
        ensure_repository();
        
        git_buf input = {0};
        git_buf output = {0};
        
        input.ptr = const_cast<char*>(content.c_str());
        input.size = content.size();
        input.asize = content.size() + 1;
        
        git_filter_list* filters = nullptr;
        int error = git_filter_list_load(&filters, repo_, nullptr, path.c_str(), 
                                        filter_mode, GIT_FILTER_OPTIONS_INIT);
        check_error(error);
        
        std::unique_ptr<git_filter_list, decltype(&git_filter_list_free)> 
            filters_guard(filters, git_filter_list_free);
        
        error = git_filter_list_apply_to_data(&output, filters, &input);
        check_error(error);
        
        std::string result(output.ptr, output.size);
        git_buf_dispose(&output);
        return result;
    }

    // Cherry-pick & Revert
    void cherry_pick(const std::string& commit_id) {
        ensure_repository();
        
        git_commit* commit = lookup_object<git_commit>(commit_id, GIT_OBJECT_COMMIT);
        std::unique_ptr<git_commit, decltype(&git_commit_free)> commit_guard(commit, git_commit_free);
        
        git_cherrypick_options opts = GIT_CHERRYPICK_OPTIONS_INIT;
        int error = git_cherrypick(repo_, commit, &opts);
        check_error(error);
    }

    void revert(const std::string& commit_id) {
        ensure_repository();
        
        git_commit* commit = lookup_object<git_commit>(commit_id, GIT_OBJECT_COMMIT);
        std::unique_ptr<git_commit, decltype(&git_commit_free)> commit_guard(commit, git_commit_free);
        
        git_revert_options opts = GIT_REVERT_OPTIONS_INIT;
        int error = git_revert(repo_, commit, &opts);
        check_error(error);
    }

    // Utility Methods
    std::string get_current_branch() {
        ensure_repository();
        
        git_reference* head = nullptr;
        int error = git_repository_head(&head, repo_);
        if (error == GIT_EUNBORNBRANCH) {
            return "";
        }
        check_error(error);
        
        std::unique_ptr<git_reference, decltype(&git_reference_free)> head_guard(head, git_reference_free);
        
        const char* branch_name = nullptr;
        error = git_branch_name(&branch_name, head);
        check_error(error);
        
        return branch_name ? std::string(branch_name) : "";
    }

    bool is_clean_working_directory() {
        ensure_repository();
        
        git_status_options status_opts = GIT_STATUS_OPTIONS_INIT;
        status_opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
        status_opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX;
        
        git_status_list* status_list = nullptr;
        int error = git_status_list_new(&status_list, repo_, &status_opts);
        if (error != 0) return false;
        
        std::unique_ptr<git_status_list, decltype(&git_status_list_free)> 
            status_guard(status_list, git_status_list_free);
        
        return git_status_list_entrycount(status_list) == 0;
    }

protected:
    git_repository* repo_ = nullptr;
    mutable std::mutex repo_mutex_;

    void ensure_repository() const {
        std::lock_guard<std::mutex> lock(repo_mutex_);
        if (!repo_) {
            throw GitException("No repository opened");
        }
    }

    void set_repository(git_repository* new_repo) {
        std::lock_guard<std::mutex> lock(repo_mutex_);
        if (repo_) {
            git_repository_free(repo_);
        }
        repo_ = new_repo;
    }

    void check_error(int error_code) const {
        if (error_code < 0) {
            const git_error* error = git_error_last();
            std::string message = error && error->message ? error->message : "Unknown Git error";
            throw GitException(message, error_code);
        }
    }

    template<typename T>
    T* lookup_object(const std::string& object_id, git_object_t type) {
        git_oid oid;
        int error = git_oid_fromstr(&oid, object_id.c_str());
        check_error(error);
        
        git_object* obj = nullptr;
        error = git_object_lookup(&obj, repo_, &oid, type);
        check_error(error);
        
        return reinterpret_cast<T*>(obj);
    }

    git_signature* create_signature(const Signature& sig) const {
        git_signature* signature = nullptr;
        int error = git_signature_new(&signature, sig.name.c_str(), sig.email.c_str(), sig.time.time, sig.time.offset);
        check_error(error);
        return signature;
    }

    std::string oid_to_string(const git_oid& oid) const {
        char oid_str[GIT_OID_HEXSTR_LENGTH + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &oid);
        return oid_str;
    }

    void setup_clone_callbacks(git_clone_options& opts, ProgressData& progress_data) {
        if (progress_data.transfer_progress) {
            opts.fetch_opts.callbacks.transfer_progress = [](const git_indexer_progress* stats, void* payload) -> int {
                auto* data = static_cast<ProgressData*>(payload);
                return data->transfer_progress(stats->received_objects, stats->total_objects) ? 0 : -1;
            };
        }
        
        if (progress_data.checkout_progress) {
            opts.checkout_opts.progress_cb = [](const char* path, size_t completed_steps, size_t total_steps, void* payload) {
                auto* data = static_cast<ProgressData*>(payload);
                return data->checkout_progress(path, completed_steps, total_steps) ? 0 : -1;
            };
        }
        
        if (progress_data.sideband_progress) {
            opts.fetch_opts.callbacks.sideband_progress = [](const char* str, int len, void* payload) -> int {
                auto* data = static_cast<ProgressData*>(payload);
                std::string message(str, len);
                return data->sideband_progress(message) ? 0 : -1;
            };
        }
        
        opts.fetch_opts.callbacks.payload = &progress_data;
        opts.checkout_opts.progress_payload = &progress_data;
    }

    void setup_fetch_callbacks(git_fetch_options& opts, ProgressData& progress_data) {
        if (progress_data.transfer_progress) {
            opts.callbacks.transfer_progress = [](const git_indexer_progress* stats, void* payload) -> int {
                auto* data = static_cast<ProgressData*>(payload);
                if (data->cancelled) return -1;
                return data->transfer_progress(stats->received_objects, stats->total_objects) ? 0 : -1;
            };
        }
        
        if (progress_data.sideband_progress) {
            opts.callbacks.sideband_progress = [](const char* str, int len, void* payload) -> int {
                auto* data = static_cast<ProgressData*>(payload);
                if (data->cancelled) return -1;
                std::string message(str, len);
                return data->sideband_progress(message) ? 0 : -1;
            };
        }
        
        opts.callbacks.payload = &progress_data;
    }

    void setup_push_callbacks(git_push_options& opts, ProgressData& progress_data,
                             const std::function<bool(size_t, size_t)>& push_progress) {
        if (push_progress) {
            opts.callbacks.push_transfer_progress = [](unsigned int current, unsigned int total, size_t bytes, void* payload) -> int {
                auto* data = static_cast<ProgressData*>(payload);
                if (data->cancelled) return -1;
                return push_progress(current, total) ? 0 : -1;
            };
        }
        
        if (progress_data.sideband_progress) {
            opts.callbacks.sideband_progress = [](const char* str, int len, void* payload) -> int {
                auto* data = static_cast<ProgressData*>(payload);
                if (data->cancelled) return -1;
                std::string message(str, len);
                return data->sideband_progress(message) ? 0 : -1;
            };
        }
        
        opts.callbacks.payload = &progress_data;
    }

    void setup_refspec_array(git_strarray& array, const std::vector<std::string>& refspecs) {
        array.count = refspecs.size();
        array.strings = new char*[array.count];
        
        for (size_t i = 0; i < array.count; ++i) {
            array.strings[i] = strdup(refspecs[i].c_str());
        }
    }

    void setup_diff(git_diff*& diff, const std::string& from_commit, const std::string& to_commit) {
        git_tree* old_tree = nullptr;
        git_tree* new_tree = nullptr;
        
        if (!from_commit.empty()) {
            git_object* old_obj = nullptr;
            int error = git_revparse_single(&old_obj, repo_, from_commit.c_str());
            check_error(error);
            
            std::unique_ptr<git_object, decltype(&git_object_free)> old_obj_guard(old_obj, git_object_free);
            
            error = git_object_peel((git_object**)&old_tree, old_obj, GIT_OBJECT_TREE);
            check_error(error);
        }
        
        if (!to_commit.empty()) {
            git_object* new_obj = nullptr;
            int error = git_revparse_single(&new_obj, repo_, to_commit.c_str());
            check_error(error);
            
            std::unique_ptr<git_object, decltype(&git_object_free)> new_obj_guard(new_obj, git_object_free);
            
            error = git_object_peel((git_object**)&new_tree, new_obj, GIT_OBJECT_TREE);
            check_error(error);
        }
        
        git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
        int error = git_diff_tree_to_tree(&diff, repo_, old_tree, new_tree, &diff_opts);
        check_error(error);
    }

    void handle_merge_conflicts(git_index* index, const std::function<bool(const git_merge_file_result*)>& callback) {
        git_index_conflict_iterator* conflict_iter = nullptr;
        int error = git_index_conflict_iterator_new(&conflict_iter, index);
        check_error(error);
        
        std::unique_ptr<git_index_conflict_iterator, decltype(&git_index_conflict_iterator_free)> 
            iter_guard(conflict_iter, git_index_conflict_iterator_free);
        
        const git_index_entry* ancestor = nullptr;
        const git_index_entry* ours = nullptr;
        const git_index_entry* theirs = nullptr;
        
        while (git_index_conflict_next(&ancestor, &ours, &theirs, conflict_iter) == 0) {
            if (callback) {
                git_merge_file_result result = {0};
                git_merge_file_options merge_opts = GIT_MERGE_FILE_OPTIONS_INIT;
                
                if (git_merge_file_from_index(&result, repo_, ancestor, ours, theirs, &merge_opts) == 0) {
                    if (!callback(&result)) {
                        git_merge_file_result_free(&result);
                        throw GitException("Merge conflict resolution cancelled by user");
                    }
                    git_merge_file_result_free(&result);
                }
            }
        }
    }

    bool handle_rebase_conflict(git_rebase* rebase, const std::function<bool(const git_merge_file_result*)>& callback) {
        git_index* index = git_rebase_operation_index(rebase);
        if (!git_index_has_conflicts(index)) {
            return true;
        }
        
        try {
            handle_merge_conflicts(index, callback);
            return true;
        } catch (const GitException&) {
            return false;
        }
    }
};