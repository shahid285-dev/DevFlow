#ifndef FILE_ENGINE_H
#define FILE_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>

using namespace std;

class FileEngine {
public:
    enum class OpenMode {
        Read,
        Write,
        Append,
        ReadWrite
    };

    struct FileInfo {
        string filename;
        string path;
        uint64_t size;
        time_t last_modified;
        bool is_readable;
        bool is_writable;
    };

    static bool createFile(const string& filepath);
    static bool deleteFile(const string& filepath);
    static bool renameFile(const string& old_path, const string& new_path);
    static bool copyFile(const string& source_path, const string& dest_path);
    static bool exists(const string& filepath);
    
    static bool writeText(const string& filepath, const string& content);
    static bool writeBinary(const string& filepath, const vector<uint8_t>& data);
    static bool appendText(const string& filepath, const string& content);
    static bool appendBinary(const string& filepath, const vector<uint8_t>& data);
    
    static string readText(const string& filepath);
    static vector<uint8_t> readBinary(const string& filepath);
    static vector<string> readLines(const string& filepath);
    
    static bool updateContent(const string& filepath, const string& new_content);
    static bool replaceInFile(const string& filepath, const string& search, const string& replace);
    
    static uint64_t getFileSize(const string& filepath);
    static time_t getLastModifiedTime(const string& filepath);
    static FileInfo getFileInfo(const string& filepath);
    
    static bool setPermissions(const string& filepath, bool readable, bool writable);
    static string getChecksum(const string& filepath);
    
    static bool truncateFile(const string& filepath, uint64_t new_size);
    static bool clearFile(const string& filepath);
    
    static bool compareFiles(const string& file1, const string& file2);
    static string getExtension(const string& filepath);
    static string getFilename(const string& filepath);

private:
    static bool openFile(const string& filepath, OpenMode mode, FILE*& file);
    static void closeFile(FILE* file);
    static string getTemporaryPath(const string& original_path);
};

#endif