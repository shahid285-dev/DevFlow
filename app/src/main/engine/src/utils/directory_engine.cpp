#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <cstring>
#include <algorithm>
#include <fnmatch.h>


#include "../include/tools/directory_engine.h"
#include "metrics_base.h"


using namespace std;

class DirectoryEngine : public MetricsBase {
private:
    bool metrics_enabled_;

public:
    DirectoryEngine() : MetricsBase("DIRECTORY_ENGINE"), metrics_enabled_(true) {}

    void enableMetrics(bool enabled) {
        metrics_enabled_ = enabled;
        MetricsBase::enableMetrics(enabled);
    }

    bool isMetricsEnabled() const {
        return metrics_enabled_;
    }

    bool createDirectory(const std::string& path) {
        if (!metrics_enabled_) {
            if (path.empty()) return false;
            return mkdir(path.c_str(), 0755) == 0;
        }

        return measure("create_directory", [&]() {
            if (path.empty()) {
                logError("create_directory", "Empty path provided");
                return false;
            }
            
            bool success = mkdir(path.c_str(), 0755) == 0;
            if (success) {
                logInfo("create_directory", "Directory created successfully", {{"path", path}});
            } else {
                logError("create_directory", "Failed to create directory", 2001, {{"path", path}});
            }
            return success;
        }, {{"path", path}});
    }

    bool createDirectories(const std::string& path) {
        if (!metrics_enabled_) {
            if (path.empty()) return false;
            std::string current_path;
            size_t pos = 0;
            
            if (path[0] == '/') {
                current_path = "/";
                pos = 1;
            }
            
            while (pos < path.length()) {
                size_t next_slash = path.find('/', pos);
                std::string segment;
                
                if (next_slash == std::string::npos) {
                    segment = path.substr(pos);
                    pos = path.length();
                } else {
                    segment = path.substr(pos, next_slash - pos);
                    pos = next_slash + 1;
                }
                
                if (segment.empty()) continue;
                
                if (!current_path.empty() && current_path.back() != '/') {
                    current_path += "/";
                }
                current_path += segment;
                
                if (!exists(current_path)) {
                    if (!createDirectory(current_path)) {
                        return false;
                    }
                }
            }
            return true;
        }

        return measure("create_directories", [&]() {
            if (path.empty()) {
                logError("create_directories", "Empty path provided");
                return false;
            }
            
            std::string current_path;
            size_t pos = 0;
            int created_count = 0;
            
            if (path[0] == '/') {
                current_path = "/";
                pos = 1;
            }
            
            while (pos < path.length()) {
                size_t next_slash = path.find('/', pos);
                std::string segment;
                
                if (next_slash == std::string::npos) {
                    segment = path.substr(pos);
                    pos = path.length();
                } else {
                    segment = path.substr(pos, next_slash - pos);
                    pos = next_slash + 1;
                }
                
                if (segment.empty()) continue;
                
                if (!current_path.empty() && current_path.back() != '/') {
                    current_path += "/";
                }
                current_path += segment;
                
                if (!exists(current_path)) {
                    if (mkdir(current_path.c_str(), 0755) != 0) {
                        logError("create_directories", "Failed to create directory segment", 2002, {{"segment", current_path}});
                        return false;
                    }
                    created_count++;
                }
            }
            
            logInfo("create_directories", "Directory hierarchy created successfully", 
                   {{"path", path}, {"directories_created", created_count}});
            return true;
        }, {{"path", path}});
    }

    bool deleteDirectory(const std::string& path) {
        if (!metrics_enabled_) {
            if (!exists(path)) return false;
            return rmdir(path.c_str()) == 0;
        }

        return measure("delete_directory", [&]() {
            if (!exists(path)) {
                logWarning("delete_directory", "Directory does not exist", {{"path", path}});
                return false;
            }
            
            bool success = rmdir(path.c_str()) == 0;
            if (success) {
                logInfo("delete_directory", "Directory deleted successfully", {{"path", path}});
            } else {
                logError("delete_directory", "Failed to delete directory", 2003, {{"path", path}});
            }
            return success;
        }, {{"path", path}});
    }

    bool deleteDirectoryRecursive(const std::string& path) {
        if (!metrics_enabled_) {
            if (!exists(path)) return false;
            return removeDirectoryInternal(path);
        }

        return measure("delete_directory_recursive", [&]() {
            if (!exists(path)) {
                logWarning("delete_directory_recursive", "Directory does not exist", {{"path", path}});
                return false;
            }
            
            bool success = removeDirectoryInternal(path);
            if (success) {
                logInfo("delete_directory_recursive", "Directory and contents deleted successfully", {{"path", path}});
            } else {
                logError("delete_directory_recursive", "Failed to delete directory recursively", 2004, {{"path", path}});
            }
            return success;
        }, {{"path", path}});
    }

    bool renameDirectory(const std::string& old_path, const std::string& new_path) {
        if (!metrics_enabled_) {
            if (!exists(old_path) || new_path.empty()) return false;
            return rename(old_path.c_str(), new_path.c_str()) == 0;
        }

        return measure("rename_directory", [&]() {
            if (!exists(old_path) || new_path.empty()) {
                logError("rename_directory", "Invalid paths provided", 2005, 
                        {{"old_path", old_path}, {"new_path", new_path}});
                return false;
            }
            
            bool success = rename(old_path.c_str(), new_path.c_str()) == 0;
            if (success) {
                logInfo("rename_directory", "Directory renamed successfully", 
                       {{"old_path", old_path}, {"new_path", new_path}});
            } else {
                logError("rename_directory", "Failed to rename directory", 2006,
                        {{"old_path", old_path}, {"new_path", new_path}});
            }
            return success;
        }, {{"old_path", old_path}, {"new_path", new_path}});
    }

    bool copyDirectory(const std::string& source_path, const std::string& dest_path) {
        if (!metrics_enabled_) {
            if (!exists(source_path) || dest_path.empty()) return false;
            if (!createDirectories(dest_path)) return false;
            return copyDirectoryInternal(source_path, dest_path);
        }

        return measure("copy_directory", [&]() {
            if (!exists(source_path) || dest_path.empty()) {
                logError("copy_directory", "Invalid source or destination path", 2007,
                        {{"source_path", source_path}, {"dest_path", dest_path}});
                return false;
            }
            
            if (!createDirectories(dest_path)) {
                logError("copy_directory", "Failed to create destination directory", 2008, {{"dest_path", dest_path}});
                return false;
            }
            
            bool success = copyDirectoryInternal(source_path, dest_path);
            if (success) {
                logInfo("copy_directory", "Directory copied successfully",
                       {{"source_path", source_path}, {"dest_path", dest_path}});
            } else {
                logError("copy_directory", "Failed to copy directory", 2009,
                        {{"source_path", source_path}, {"dest_path", dest_path}});
            }
            return success;
        }, {{"source_path", source_path}, {"dest_path", dest_path}});
    }

    bool exists(const std::string& path) {
        struct stat buffer;
        bool dir_exists = stat(path.c_str(), &buffer) == 0 && S_ISDIR(buffer.st_mode);
        
        if (metrics_enabled_ && !dir_exists) {
            logDebug("directory_exists", "Directory does not exist", {{"path", path}});
        }
        return dir_exists;
    }

    std::vector<DirectoryEngine::DirEntry> listEntries(const std::string& path) {
        if (!metrics_enabled_) {
            std::vector<DirEntry> entries;
            DIR* dir = opendir(path.c_str());
            if (!dir) return entries;
            
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
                
                DirEntry dir_entry;
                dir_entry.name = entry->d_name;
                dir_entry.path = combinePaths(path, entry->d_name);
                
                struct stat stat_buf;
                if (stat(dir_entry.path.c_str(), &stat_buf) == 0) {
                    dir_entry.is_directory = S_ISDIR(stat_buf.st_mode);
                    dir_entry.is_file = S_ISREG(stat_buf.st_mode);
                    dir_entry.size = dir_entry.is_file ? static_cast<uint64_t>(stat_buf.st_size) : 0;
                    dir_entry.last_modified = stat_buf.st_mtime;
                }
                entries.push_back(dir_entry);
            }
            closedir(dir);
            return entries;
        }

        return measure("list_entries", [&]() -> std::vector<DirEntry> {
            std::vector<DirEntry> entries;
            DIR* dir = opendir(path.c_str());
            if (!dir) {
                logError("list_entries", "Failed to open directory", 2010, {{"path", path}});
                return entries;
            }
            
            struct dirent* entry;
            int entry_count = 0;
            while ((entry = readdir(dir)) != nullptr) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
                
                DirEntry dir_entry;
                dir_entry.name = entry->d_name;
                dir_entry.path = combinePaths(path, entry->d_name);
                
                struct stat stat_buf;
                if (stat(dir_entry.path.c_str(), &stat_buf) == 0) {
                    dir_entry.is_directory = S_ISDIR(stat_buf.st_mode);
                    dir_entry.is_file = S_ISREG(stat_buf.st_mode);
                    dir_entry.size = dir_entry.is_file ? static_cast<uint64_t>(stat_buf.st_size) : 0;
                    dir_entry.last_modified = stat_buf.st_mtime;
                }
                entries.push_back(dir_entry);
                entry_count++;
            }
            closedir(dir);
            
            logInfo("list_entries", "Directory entries listed successfully",
                   {{"path", path}, {"entry_count", entry_count}});
            return entries;
        }, {{"path", path}});
    }

    std::vector<std::string> listFiles(const std::string& path) {
        if (!metrics_enabled_) {
            std::vector<std::string> files;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_file) files.push_back(entry.name);
            }
            return files;
        }

        return measure("list_files", [&]() -> std::vector<std::string> {
            auto entries = listEntries(path);
            std::vector<std::string> files;
            for (const auto& entry : entries) {
                if (entry.is_file) files.push_back(entry.name);
            }
            
            logInfo("list_files", "Directory files listed successfully",
                   {{"path", path}, {"file_count", files.size()}});
            return files;
        }, {{"path", path}});
    }

    std::vector<std::string> listDirectories(const std::string& path) {
        if (!metrics_enabled_) {
            std::vector<std::string> directories;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_directory) directories.push_back(entry.name);
            }
            return directories;
        }

        return measure("list_directories", [&]() -> std::vector<std::string> {
            auto entries = listEntries(path);
            std::vector<std::string> directories;
            for (const auto& entry : entries) {
                if (entry.is_directory) directories.push_back(entry.name);
            }
            
            logInfo("list_directories", "Subdirectories listed successfully",
                   {{"path", path}, {"directory_count", directories.size()}});
            return directories;
        }, {{"path", path}});
    }

    std::vector<std::string> listAll(const std::string& path) {
        if (!metrics_enabled_) {
            std::vector<std::string> all;
            auto entries = listEntries(path);
            for (const auto& entry : entries) all.push_back(entry.name);
            return all;
        }

        return measure("list_all", [&]() -> std::vector<std::string> {
            auto entries = listEntries(path);
            std::vector<std::string> all;
            for (const auto& entry : entries) all.push_back(entry.name);
            
            logInfo("list_all", "All directory entries listed successfully",
                   {{"path", path}, {"total_count", all.size()}});
            return all;
        }, {{"path", path}});
    }

    bool isEmpty(const std::string& path) {
        if (!metrics_enabled_) {
            auto entries = listEntries(path);
            return entries.empty();
        }

        return measure("is_empty", [&]() {
            auto entries = listEntries(path);
            bool empty = entries.empty();
            
            logDebug("is_empty", empty ? "Directory is empty" : "Directory is not empty", {{"path", path}});
            return empty;
        }, {{"path", path}});
    }

    uint64_t getDirectorySize(const std::string& path) {
        if (!metrics_enabled_) {
            DirInfo info = getDirectoryInfo(path);
            return info.total_size;
        }

        return measure("get_directory_size", [&]() -> uint64_t {
            DirInfo info = getDirectoryInfo(path);
            
            logInfo("get_directory_size", "Directory size calculated",
                   {{"path", path}, {"size_bytes", info.total_size}});
            return info.total_size;
        }, {{"path", path}});
    }

    DirectoryEngine::DirInfo getDirectoryInfo(const std::string& path) {
        if (!metrics_enabled_) {
            DirInfo info;
            info.path = path;
            info.total_files = 0;
            info.total_directories = 0;
            info.total_size = 0;
            info.last_modified = 0;
            collectDirectoryInfo(path, info);
            return info;
        }

        return measure("get_directory_info", [&]() -> DirInfo {
            DirInfo info;
            info.path = path;
            info.total_files = 0;
            info.total_directories = 0;
            info.total_size = 0;
            info.last_modified = 0;
            
            collectDirectoryInfo(path, info);
            
            logInfo("get_directory_info", "Directory information collected",
                   {{"path", path}, {"files", info.total_files}, 
                    {"directories", info.total_directories}, {"size", info.total_size}});
            return info;
        }, {{"path", path}});
    }

    bool setPermissions(const std::string& path, bool readable, bool writable, bool executable) {
        if (!metrics_enabled_) {
            mode_t mode = 0;
            if (readable) mode |= S_IRUSR | S_IRGRP | S_IROTH;
            if (writable) mode |= S_IWUSR | S_IWGRP | S_IWOTH;
            if (executable) mode |= S_IXUSR | S_IXGRP | S_IXOTH;
            return chmod(path.c_str(), mode) == 0;
        }

        return measure("set_permissions", [&]() {
            mode_t mode = 0;
            if (readable) mode |= S_IRUSR | S_IRGRP | S_IROTH;
            if (writable) mode |= S_IWUSR | S_IWGRP | S_IWOTH;
            if (executable) mode |= S_IXUSR | S_IXGRP | S_IXOTH;
            
            bool success = chmod(path.c_str(), mode) == 0;
            if (success) {
                logInfo("set_permissions", "Directory permissions updated successfully",
                       {{"path", path}, {"readable", readable}, {"writable", writable}, {"executable", executable}});
            } else {
                logError("set_permissions", "Failed to set directory permissions", 2011,
                        {{"path", path}, {"readable", readable}, {"writable", writable}, {"executable", executable}});
            }
            return success;
        }, {{"path", path}, {"readable", readable}, {"writable", writable}, {"executable", executable}});
    }

    bool setOwner(const std::string& path, uint32_t user_id, uint32_t group_id) {
        if (!metrics_enabled_) {
            return chown(path.c_str(), static_cast<uid_t>(user_id), static_cast<gid_t>(group_id)) == 0;
        }

        return measure("set_owner", [&]() {
            bool success = chown(path.c_str(), static_cast<uid_t>(user_id), static_cast<gid_t>(group_id)) == 0;
            if (success) {
                logInfo("set_owner", "Directory ownership updated successfully",
                       {{"path", path}, {"user_id", user_id}, {"group_id", group_id}});
            } else {
                logError("set_owner", "Failed to set directory ownership", 2012,
                        {{"path", path}, {"user_id", user_id}, {"group_id", group_id}});
            }
            return success;
        }, {{"path", path}, {"user_id", user_id}, {"group_id", group_id}});
    }

    std::string getCurrentWorkingDirectory() {
        if (!metrics_enabled_) {
            char buffer[4096];
            return getcwd(buffer, sizeof(buffer)) ? std::string(buffer) : "";
        }

        return measure("get_cwd", [&]() -> std::string {
            char buffer[4096];
            std::string cwd = getcwd(buffer, sizeof(buffer)) ? std::string(buffer) : "";
            
            logDebug("get_cwd", "Current working directory retrieved", {{"cwd", cwd}});
            return cwd;
        });
    }

    bool setCurrentWorkingDirectory(const std::string& path) {
        if (!metrics_enabled_) {
            return chdir(path.c_str()) == 0;
        }

        return measure("set_cwd", [&]() {
            bool success = chdir(path.c_str()) == 0;
            if (success) {
                logInfo("set_cwd", "Current working directory changed successfully", {{"path", path}});
            } else {
                logError("set_cwd", "Failed to change current working directory", 2013, {{"path", path}});
            }
            return success;
        }, {{"path", path}});
    }

    std::string getParentPath(const std::string& path) {
        if (path.empty() || path == "/") return "";
        size_t last_slash = path.find_last_of('/');
        if (last_slash == 0) return "/";
        if (last_slash == std::string::npos) return "";
        return path.substr(0, last_slash);
    }

    std::string combinePaths(const std::string& path1, const std::string& path2) {
        if (path1.empty()) return path2;
        if (path2.empty()) return path1;
        
        if (path1.back() == '/') {
            if (path2.front() == '/') return path1 + path2.substr(1);
            return path1 + path2;
        } else {
            if (path2.front() == '/') return path1 + path2;
            return path1 + "/" + path2;
        }
    }

    std::string normalizePath(const std::string& path) {
        std::string result = path;
        size_t pos;
        while ((pos = result.find("//")) != std::string::npos) result.replace(pos, 2, "/");
        if (result.length() > 1 && result.back() == '/') result.pop_back();
        return result;
    }

    bool moveDirectory(const std::string& source_path, const std::string& dest_path) {
        return renameDirectory(source_path, dest_path);
    }

    bool cleanDirectory(const std::string& path) {
        if (!metrics_enabled_) {
            if (!exists(path)) return false;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    if (!deleteDirectoryRecursive(entry.path)) return false;
                } else {
                    if (std::remove(entry.path.c_str()) != 0) return false;
                }
            }
            return true;
        }

        return measure("clean_directory", [&]() {
            if (!exists(path)) {
                logWarning("clean_directory", "Directory does not exist", {{"path", path}});
                return false;
            }
            
            auto entries = listEntries(path);
            int deleted_count = 0;
            int error_count = 0;
            
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    if (!deleteDirectoryRecursive(entry.path)) error_count++;
                    else deleted_count++;
                } else {
                    if (std::remove(entry.path.c_str()) != 0) error_count++;
                    else deleted_count++;
                }
            }
            
            if (error_count > 0) {
                logError("clean_directory", "Failed to clean some directory contents", 2014,
                        {{"path", path}, {"deleted", deleted_count}, {"errors", error_count}});
                return false;
            }
            
            logInfo("clean_directory", "Directory cleaned successfully",
                   {{"path", path}, {"items_removed", deleted_count}});
            return true;
        }, {{"path", path}});
    }

    std::vector<std::string> findFiles(const std::string& path, const std::string& pattern) {
        if (!metrics_enabled_) {
            std::vector<std::string> found_files;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    auto sub_files = findFiles(entry.path, pattern);
                    found_files.insert(found_files.end(), sub_files.begin(), sub_files.end());
                } else if (entry.is_file && matchesPattern(entry.name, pattern)) {
                    found_files.push_back(entry.path);
                }
            }
            return found_files;
        }

        return measure("find_files", [&]() -> std::vector<std::string> {
            std::vector<std::string> found_files;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    auto sub_files = findFiles(entry.path, pattern);
                    found_files.insert(found_files.end(), sub_files.begin(), sub_files.end());
                } else if (entry.is_file && matchesPattern(entry.name, pattern)) {
                    found_files.push_back(entry.path);
                }
            }
            
            logInfo("find_files", "File search completed",
                   {{"path", path}, {"pattern", pattern}, {"files_found", found_files.size()}});
            return found_files;
        }, {{"path", path}, {"pattern", pattern}});
    }

    std::vector<std::string> findDirectories(const std::string& path, const std::string& pattern) {
        if (!metrics_enabled_) {
            std::vector<std::string> found_dirs;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    if (matchesPattern(entry.name, pattern)) found_dirs.push_back(entry.path);
                    auto sub_dirs = findDirectories(entry.path, pattern);
                    found_dirs.insert(found_dirs.end(), sub_dirs.begin(), sub_dirs.end());
                }
            }
            return found_dirs;
        }

        return measure("find_directories", [&]() -> std::vector<std::string> {
            std::vector<std::string> found_dirs;
            auto entries = listEntries(path);
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    if (matchesPattern(entry.name, pattern)) found_dirs.push_back(entry.path);
                    auto sub_dirs = findDirectories(entry.path, pattern);
                    found_dirs.insert(found_dirs.end(), sub_dirs.begin(), sub_dirs.end());
                }
            }
            
            logInfo("find_directories", "Directory search completed",
                   {{"path", path}, {"pattern", pattern}, {"directories_found", found_dirs.size()}});
            return found_dirs;
        }, {{"path", path}, {"pattern", pattern}});
    }

    time_t getLastModifiedTime(const std::string& path) {
        if (!metrics_enabled_) {
            struct stat stat_buf;
            return stat(path.c_str(), &stat_buf) == 0 ? stat_buf.st_mtime : 0;
        }

        return measure("get_last_modified", [&]() -> time_t {
            struct stat stat_buf;
            time_t mod_time = stat(path.c_str(), &stat_buf) == 0 ? stat_buf.st_mtime : 0;
            
            logDebug("get_last_modified", "Last modified time retrieved", {{"path", path}, {"timestamp", mod_time}});
            return mod_time;
        }, {{"path", path}});
    }

    bool setLastModifiedTime(const std::string& path, time_t mod_time) {
        if (!metrics_enabled_) {
            struct utimbuf times;
            times.actime = mod_time;
            times.modtime = mod_time;
            return utime(path.c_str(), &times) == 0;
        }

        return measure("set_last_modified", [&]() {
            struct utimbuf times;
            times.actime = mod_time;
            times.modtime = mod_time;
            
            bool success = utime(path.c_str(), &times) == 0;
            if (success) {
                logInfo("set_last_modified", "Directory modification time updated successfully",
                       {{"path", path}, {"timestamp", mod_time}});
            } else {
                logError("set_last_modified", "Failed to set directory modification time", 2015,
                        {{"path", path}, {"timestamp", mod_time}});
            }
            return success;
        }, {{"path", path}, {"timestamp", mod_time}});
    }

private:
    bool removeDirectoryInternal(const std::string& path) {
        auto entries = listEntries(path);
        for (const auto& entry : entries) {
            if (entry.is_directory) {
                if (!removeDirectoryInternal(entry.path)) return false;
            } else {
                if (std::remove(entry.path.c_str()) != 0) return false;
            }
        }
        return deleteDirectory(path);
    }

    bool copyDirectoryInternal(const std::string& source, const std::string& dest) {
        auto entries = listEntries(source);
        for (const auto& entry : entries) {
            std::string dest_path = combinePaths(dest, entry.name);
            if (entry.is_directory) {
                if (!createDirectory(dest_path)) return false;
                if (!copyDirectoryInternal(entry.path, dest_path)) return false;
            } else if (entry.is_file) {
                std::ifstream src_file(entry.path, std::ios::binary);
                std::ofstream dest_file(dest_path, std::ios::binary);
                if (!src_file.is_open() || !dest_file.is_open()) return false;
                dest_file << src_file.rdbuf();
                src_file.close();
                dest_file.close();
            }
        }
        return true;
    }

    void collectDirectoryInfo(const std::string& path, DirInfo& info) {
        auto entries = listEntries(path);
        for (const auto& entry : entries) {
            if (entry.is_directory) {
                info.total_directories++;
                collectDirectoryInfo(entry.path, info);
            } else if (entry.is_file) {
                info.total_files++;
                info.total_size += entry.size;
            }
            if (entry.last_modified > info.last_modified) info.last_modified = entry.last_modified;
        }
    }

    bool matchesPattern(const std::string& filename, const std::string& pattern) {
        return fnmatch(pattern.c_str(), filename.c_str(), 0) == 0;
    }
};