#ifndef DIRECTORY_ENGINE_H
#define DIRECTORY_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>

class DirectoryEngine {
public:
    struct DirEntry {
        std::string name;
        std::string path;
        bool is_directory;
        bool is_file;
        uint64_t size;
        time_t last_modified;
    };

    struct DirInfo {
        std::string path;
        uint64_t total_files;
        uint64_t total_directories;
        uint64_t total_size;
        time_t last_modified;
    };

    static bool createDirectory(const std::string& path);
    static bool createDirectories(const std::string& path);
    static bool deleteDirectory(const std::string& path);
    static bool deleteDirectoryRecursive(const std::string& path);
    static bool renameDirectory(const std::string& old_path, const std::string& new_path);
    static bool copyDirectory(const std::string& source_path, const std::string& dest_path);
    static bool exists(const std::string& path);
    
    static std::vector<DirEntry> listEntries(const std::string& path);
    static std::vector<std::string> listFiles(const std::string& path);
    static std::vector<std::string> listDirectories(const std::string& path);
    static std::vector<std::string> listAll(const std::string& path);
    
    static bool isEmpty(const std::string& path);
    static uint64_t getDirectorySize(const std::string& path);
    static DirInfo getDirectoryInfo(const std::string& path);
    
    static bool setPermissions(const std::string& path, bool readable, bool writable, bool executable);
    static bool setOwner(const std::string& path, uint32_t user_id, uint32_t group_id);
    
    static std::string getCurrentWorkingDirectory();
    static bool setCurrentWorkingDirectory(const std::string& path);
    
    static std::string getParentPath(const std::string& path);
    static std::string combinePaths(const std::string& path1, const std::string& path2);
    static std::string normalizePath(const std::string& path);
    
    static bool moveDirectory(const std::string& source_path, const std::string& dest_path);
    static bool cleanDirectory(const std::string& path);
    
    static std::vector<std::string> findFiles(const std::string& path, const std::string& pattern);
    static std::vector<std::string> findDirectories(const std::string& path, const std::string& pattern);
    
    static time_t getLastModifiedTime(const std::string& path);
    static bool setLastModifiedTime(const std::string& path, time_t mod_time);

private:
    static bool removeDirectoryInternal(const std::string& path);
    static bool copyDirectoryInternal(const std::string& source, const std::string& dest);
    static void collectDirectoryInfo(const std::string& path, DirInfo& info);
    static bool matchesPattern(const std::string& filename, const std::string& pattern);
};

#endif