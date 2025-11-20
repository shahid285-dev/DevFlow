#include "../include/tools/directory_engine.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <cstring>
#include <algorithm>
#include <fnmatch.h>


using namespace std;

bool DirectoryEngine::createDirectory(const std::string& path) {
    if (path.empty()) return false;
    return mkdir(path.c_str(), 0755) == 0;
}

bool DirectoryEngine::createDirectories(const std::string& path) {
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

bool DirectoryEngine::deleteDirectory(const std::string& path) {
    if (!exists(path)) return false;
    return rmdir(path.c_str()) == 0;
}

bool DirectoryEngine::deleteDirectoryRecursive(const std::string& path) {
    if (!exists(path)) return false;
    return removeDirectoryInternal(path);
}

bool DirectoryEngine::renameDirectory(const std::string& old_path, const std::string& new_path) {
    if (!exists(old_path) || new_path.empty()) return false;
    return rename(old_path.c_str(), new_path.c_str()) == 0;
}

bool DirectoryEngine::copyDirectory(const std::string& source_path, const std::string& dest_path) {
    if (!exists(source_path) || dest_path.empty()) return false;
    
    if (!createDirectories(dest_path)) {
        return false;
    }
    
    return copyDirectoryInternal(source_path, dest_path);
}

bool DirectoryEngine::exists(const std::string& path) {
    struct stat buffer;
    if (stat(path.c_str(), &buffer) != 0) return false;
    return S_ISDIR(buffer.st_mode);
}

std::vector<DirectoryEngine::DirEntry> DirectoryEngine::listEntries(const std::string& path) {
    std::vector<DirEntry> entries;
    
    DIR* dir = opendir(path.c_str());
    if (!dir) return entries;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
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

std::vector<std::string> DirectoryEngine::listFiles(const std::string& path) {
    std::vector<std::string> files;
    auto entries = listEntries(path);
    
    for (const auto& entry : entries) {
        if (entry.is_file) {
            files.push_back(entry.name);
        }
    }
    
    return files;
}

std::vector<std::string> DirectoryEngine::listDirectories(const std::string& path) {
    std::vector<std::string> directories;
    auto entries = listEntries(path);
    
    for (const auto& entry : entries) {
        if (entry.is_directory) {
            directories.push_back(entry.name);
        }
    }
    
    return directories;
}

std::vector<std::string> DirectoryEngine::listAll(const std::string& path) {
    std::vector<std::string> all;
    auto entries = listEntries(path);
    
    for (const auto& entry : entries) {
        all.push_back(entry.name);
    }
    
    return all;
}

bool DirectoryEngine::isEmpty(const std::string& path) {
    auto entries = listEntries(path);
    return entries.empty();
}

uint64_t DirectoryEngine::getDirectorySize(const std::string& path) {
    DirInfo info = getDirectoryInfo(path);
    return info.total_size;
}

DirectoryEngine::DirInfo DirectoryEngine::getDirectoryInfo(const std::string& path) {
    DirInfo info;
    info.path = path;
    info.total_files = 0;
    info.total_directories = 0;
    info.total_size = 0;
    info.last_modified = 0;
    
    collectDirectoryInfo(path, info);
    return info;
}

bool DirectoryEngine::setPermissions(const std::string& path, bool readable, bool writable, bool executable) {
    mode_t mode = 0;
    if (readable) mode |= S_IRUSR | S_IRGRP | S_IROTH;
    if (writable) mode |= S_IWUSR | S_IWGRP | S_IWOTH;
    if (executable) mode |= S_IXUSR | S_IXGRP | S_IXOTH;
    
    return chmod(path.c_str(), mode) == 0;
}

bool DirectoryEngine::setOwner(const std::string& path, uint32_t user_id, uint32_t group_id) {
    return chown(path.c_str(), static_cast<uid_t>(user_id), static_cast<gid_t>(group_id)) == 0;
}

std::string DirectoryEngine::getCurrentWorkingDirectory() {
    char buffer[4096];
    if (getcwd(buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return "";
}

bool DirectoryEngine::setCurrentWorkingDirectory(const std::string& path) {
    return chdir(path.c_str()) == 0;
}

std::string DirectoryEngine::getParentPath(const std::string& path) {
    if (path.empty() || path == "/") return "";
    
    size_t last_slash = path.find_last_of('/');
    if (last_slash == 0) return "/";
    if (last_slash == std::string::npos) return "";
    
    return path.substr(0, last_slash);
}

std::string DirectoryEngine::combinePaths(const std::string& path1, const std::string& path2) {
    if (path1.empty()) return path2;
    if (path2.empty()) return path1;
    
    if (path1.back() == '/') {
        if (path2.front() == '/') {
            return path1 + path2.substr(1);
        }
        return path1 + path2;
    } else {
        if (path2.front() == '/') {
            return path1 + path2;
        }
        return path1 + "/" + path2;
    }
}

std::string DirectoryEngine::normalizePath(const std::string& path) {
    std::string result = path;
    
    size_t pos;
    while ((pos = result.find("//")) != std::string::npos) {
        result.replace(pos, 2, "/");
    }
    
    if (result.length() > 1 && result.back() == '/') {
        result.pop_back();
    }
    
    return result;
}

bool DirectoryEngine::moveDirectory(const std::string& source_path, const std::string& dest_path) {
    return renameDirectory(source_path, dest_path);
}

bool DirectoryEngine::cleanDirectory(const std::string& path) {
    if (!exists(path)) return false;
    
    auto entries = listEntries(path);
    for (const auto& entry : entries) {
        if (entry.is_directory) {
            if (!deleteDirectoryRecursive(entry.path)) {
                return false;
            }
        } else {
            if (std::remove(entry.path.c_str()) != 0) {
                return false;
            }
        }
    }
    
    return true;
}

std::vector<std::string> DirectoryEngine::findFiles(const std::string& path, const std::string& pattern) {
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

std::vector<std::string> DirectoryEngine::findDirectories(const std::string& path, const std::string& pattern) {
    std::vector<std::string> found_dirs;
    auto entries = listEntries(path);
    
    for (const auto& entry : entries) {
        if (entry.is_directory) {
            if (matchesPattern(entry.name, pattern)) {
                found_dirs.push_back(entry.path);
            }
            
            auto sub_dirs = findDirectories(entry.path, pattern);
            found_dirs.insert(found_dirs.end(), sub_dirs.begin(), sub_dirs.end());
        }
    }
    
    return found_dirs;
}

time_t DirectoryEngine::getLastModifiedTime(const std::string& path) {
    struct stat stat_buf;
    if (stat(path.c_str(), &stat_buf) != 0) return 0;
    return stat_buf.st_mtime;
}

bool DirectoryEngine::setLastModifiedTime(const std::string& path, time_t mod_time) {
    struct utimbuf times;
    times.actime = mod_time;
    times.modtime = mod_time;
    
    return utime(path.c_str(), &times) == 0;
}

bool DirectoryEngine::removeDirectoryInternal(const std::string& path) {
    auto entries = listEntries(path);
    
    for (const auto& entry : entries) {
        if (entry.is_directory) {
            if (!removeDirectoryInternal(entry.path)) {
                return false;
            }
        } else {
            if (std::remove(entry.path.c_str()) != 0) {
                return false;
            }
        }
    }
    
    return deleteDirectory(path);
}

bool DirectoryEngine::copyDirectoryInternal(const std::string& source, const std::string& dest) {
    auto entries = listEntries(source);
    
    for (const auto& entry : entries) {
        std::string dest_path = combinePaths(dest, entry.name);
        
        if (entry.is_directory) {
            if (!createDirectory(dest_path)) {
                return false;
            }
            if (!copyDirectoryInternal(entry.path, dest_path)) {
                return false;
            }
        } else if (entry.is_file) {
            std::ifstream src_file(entry.path, std::ios::binary);
            std::ofstream dest_file(dest_path, std::ios::binary);
            
            if (!src_file.is_open() || !dest_file.is_open()) {
                return false;
            }
            
            dest_file << src_file.rdbuf();
            src_file.close();
            dest_file.close();
        }
    }
    
    return true;
}

void DirectoryEngine::collectDirectoryInfo(const std::string& path, DirInfo& info) {
    auto entries = listEntries(path);
    
    for (const auto& entry : entries) {
        if (entry.is_directory) {
            info.total_directories++;
            collectDirectoryInfo(entry.path, info);
        } else if (entry.is_file) {
            info.total_files++;
            info.total_size += entry.size;
        }
        
        if (entry.last_modified > info.last_modified) {
            info.last_modified = entry.last_modified;
        }
    }
}

bool DirectoryEngine::matchesPattern(const std::string& filename, const std::string& pattern) {
    return fnmatch(pattern.c_str(), filename.c_str(), 0) == 0;
}