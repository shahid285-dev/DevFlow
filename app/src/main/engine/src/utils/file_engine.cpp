#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/md5.h>

#include "../include/tools/file_engine.hpp"
#include "metrics_base.hpp"

using namespace std;

class FileEngine : public MetricsBase {
public:
    FileEngine() : MetricsBase("FILE_ENGINE") {}
    
    bool createFile(const string& filepath) {
        return measure("create_file", [&]() {
            if (filepath.empty()) {
                logError("create_file", "Empty file path provided");
                return false;
            }
            
            ofstream file(filepath);
            if (!file.is_open()) {
                logError("create_file", "Failed to create file", 1001, {{"path", filepath}});
                return false;
            }
            
            file.close();
            logInfo("create_file", "File created successfully", {{"path", filepath}});
            return true;
        }, {{"path", filepath}});
    }

    bool deleteFile(const string& filepath) {
        return measure("delete_file", [&]() {
            if (!exists(filepath)) {
                logWarning("delete_file", "File does not exist", {{"path", filepath}});
                return false;
            }
            
            bool success = remove(filepath.c_str()) == 0;
            if (success) {
                logInfo("delete_file", "File deleted successfully", {{"path", filepath}});
            } else {
                logError("delete_file", "Failed to delete file", 1002, {{"path", filepath}});
            }
            return success;
        }, {{"path", filepath}});
    }

    bool renameFile(const string& old_path, const string& new_path) {
        return measure("rename_file", [&]() {
            if (!exists(old_path) || new_path.empty()) {
                logError("rename_file", "Invalid paths provided", 1003, 
                        {{"old_path", old_path}, {"new_path", new_path}});
                return false;
            }
            
            bool success = rename(old_path.c_str(), new_path.c_str()) == 0;
            if (success) {
                logInfo("rename_file", "File renamed successfully", 
                       {{"old_path", old_path}, {"new_path", new_path}});
            } else {
                logError("rename_file", "Failed to rename file", 1004,
                        {{"old_path", old_path}, {"new_path", new_path}});
            }
            return success;
        }, {{"old_path", old_path}, {"new_path", new_path}});
    }

    bool copyFile(const string& source_path, const string& dest_path) {
        return measure("copy_file", [&]() {
            if (!exists(source_path) || dest_path.empty()) {
                logError("copy_file", "Invalid source or destination path", 1005,
                        {{"source_path", source_path}, {"dest_path", dest_path}});
                return false;
            }
            
            ifstream source(source_path, ios::binary);
            ofstream dest(dest_path, ios::binary);
            
            if (!source.is_open() || !dest.is_open()) {
                logError("copy_file", "Failed to open source or destination file", 1006,
                        {{"source_path", source_path}, {"dest_path", dest_path}});
                return false;
            }
            
            dest << source.rdbuf();
            
            source.close();
            dest.close();
            
            uint64_t file_size = getFileSize(source_path);
            logInfo("copy_file", "File copied successfully",
                   {{"source_path", source_path}, {"dest_path", dest_path}, {"size", file_size}});
            return true;
        }, {{"source_path", source_path}, {"dest_path", dest_path}});
    }

    bool exists(const string& filepath) {
        struct stat buffer;
        bool exists = stat(filepath.c_str(), &buffer) == 0;
        
        if (!exists) {
            logDebug("file_exists", "File does not exist", {{"path", filepath}});
        }
        return exists;
    }

    bool writeText(const string& filepath, const string& content) {
        return measure("write_text", [&]() {
            ofstream file(filepath);
            if (!file.is_open()) {
                logError("write_text", "Failed to open file for writing", 1007, {{"path", filepath}});
                return false;
            }
            
            file << content;
            file.close();
            
            logInfo("write_text", "Text written to file successfully",
                   {{"path", filepath}, {"content_length", content.length()}});
            return true;
        }, {{"path", filepath}, {"content_length", content.length()}});
    }

    bool writeBinary(const string& filepath, const vector<uint8_t>& data) {
        return measure("write_binary", [&]() {
            ofstream file(filepath, ios::binary);
            if (!file.is_open()) {
                logError("write_binary", "Failed to open file for binary writing", 1008, {{"path", filepath}});
                return false;
            }
            
            file.write(reinterpret_cast<const char*>(data.data()), data.size());
            file.close();
            
            logInfo("write_binary", "Binary data written to file successfully",
                   {{"path", filepath}, {"data_size", data.size()}});
            return true;
        }, {{"path", filepath}, {"data_size", data.size()}});
    }

    bool appendText(const string& filepath, const string& content) {
        return measure("append_text", [&]() {
            ofstream file(filepath, ios::app);
            if (!file.is_open()) {
                logError("append_text", "Failed to open file for appending", 1009, {{"path", filepath}});
                return false;
            }
            
            file << content;
            file.close();
            
            logInfo("append_text", "Text appended to file successfully",
                   {{"path", filepath}, {"appended_length", content.length()}});
            return true;
        }, {{"path", filepath}, {"appended_length", content.length()}});
    }

    bool appendBinary(const string& filepath, const vector<uint8_t>& data) {
        return measure("append_binary", [&]() {
            ofstream file(filepath, ios::binary | ios::app);
            if (!file.is_open()) {
                logError("append_binary", "Failed to open file for binary appending", 1010, {{"path", filepath}});
                return false;
            }
            
            file.write(reinterpret_cast<const char*>(data.data()), data.size());
            file.close();
            
            logInfo("append_binary", "Binary data appended to file successfully",
                   {{"path", filepath}, {"appended_size", data.size()}});
            return true;
        }, {{"path", filepath}, {"appended_size", data.size()}});
    }

    string readText(const string& filepath) {
        return measure("read_text", [&]() -> string {
            ifstream file(filepath);
            if (!file.is_open()) {
                logError("read_text", "Failed to open file for reading", 1011, {{"path", filepath}});
                return "";
            }
            
            stringstream buffer;
            buffer << file.rdbuf();
            file.close();
            
            string content = buffer.str();
            logInfo("read_text", "Text read from file successfully",
                   {{"path", filepath}, {"content_length", content.length()}});
            return content;
        }, {{"path", filepath}});
    }

    vector<uint8_t> readBinary(const string& filepath) {
        return measure("read_binary", [&]() -> vector<uint8_t> {
            ifstream file(filepath, ios::binary | ios::ate);
            if (!file.is_open()) {
                logError("read_binary", "Failed to open file for binary reading", 1012, {{"path", filepath}});
                return {};
            }
            
            streamsize size = file.tellg();
            file.seekg(0, ios::beg);
            
            vector<uint8_t> buffer(size);
            if (size > 0) {
                file.read(reinterpret_cast<char*>(buffer.data()), size);
            }
            file.close();
            
            logInfo("read_binary", "Binary data read from file successfully",
                   {{"path", filepath}, {"data_size", size}});
            return buffer;
        }, {{"path", filepath}});
    }

    vector<string> readLines(const string& filepath) {
        return measure("read_lines", [&]() -> vector<string> {
            vector<string> lines;
            ifstream file(filepath);
            
            if (!file.is_open()) {
                logError("read_lines", "Failed to open file for line reading", 1013, {{"path", filepath}});
                return lines;
            }
            
            string line;
            while (getline(file, line)) {
                lines.push_back(line);
            }
            
            file.close();
            
            logInfo("read_lines", "Lines read from file successfully",
                   {{"path", filepath}, {"line_count", lines.size()}});
            return lines;
        }, {{"path", filepath}});
    }

    bool updateContent(const string& filepath, const string& new_content) {
        return measure("update_content", [&]() {
            bool success = writeText(filepath, new_content);
            if (success) {
                logInfo("update_content", "File content updated successfully",
                       {{"path", filepath}, {"new_content_length", new_content.length()}});
            }
            return success;
        }, {{"path", filepath}, {"new_content_length", new_content.length()}});
    }

    bool replaceInFile(const string& filepath, const string& search, const string& replace) {
        return measure("replace_in_file", [&]() {
            string content = readText(filepath);
            if (content.empty() && !exists(filepath)) {
                logError("replace_in_file", "File is empty or doesn't exist", 1014, {{"path", filepath}});
                return false;
            }
            
            size_t replace_count = 0;
            size_t pos = 0;
            while ((pos = content.find(search, pos)) != string::npos) {
                content.replace(pos, search.length(), replace);
                pos += replace.length();
                replace_count++;
            }
            
            bool success = writeText(filepath, content);
            if (success) {
                logInfo("replace_in_file", "Text replaced in file successfully",
                       {{"path", filepath}, {"replace_count", replace_count}, 
                        {"search_term", search}, {"replacement", replace}});
            }
            return success;
        }, {{"path", filepath}, {"search_term", search}, {"replacement", replace}});
    }

    uint64_t getFileSize(const string& filepath) {
        return measure("get_file_size", [&]() -> uint64_t {
            struct stat stat_buf;
            if (stat(filepath.c_str(), &stat_buf) != 0) {
                logDebug("get_file_size", "Failed to get file size", {{"path", filepath}});
                return 0;
            }
            return static_cast<uint64_t>(stat_buf.st_size);
        }, {{"path", filepath}});
    }

    time_t getLastModifiedTime(const string& filepath) {
        return measure("get_last_modified", [&]() -> time_t {
            struct stat stat_buf;
            if (stat(filepath.c_str(), &stat_buf) != 0) {
                logDebug("get_last_modified", "Failed to get last modified time", {{"path", filepath}});
                return 0;
            }
            return stat_buf.st_mtime;
        }, {{"path", filepath}});
    }

    FileInfo getFileInfo(const string& filepath) {
        return measure("get_file_info", [&]() -> FileInfo {
            FileInfo info;
            info.path = filepath;
            info.filename = getFilename(filepath);
            
            struct stat stat_buf;
            if (stat(filepath.c_str(), &stat_buf) == 0) {
                info.size = static_cast<uint64_t>(stat_buf.st_size);
                info.last_modified = stat_buf.st_mtime;
                info.is_readable = access(filepath.c_str(), R_OK) == 0;
                info.is_writable = access(filepath.c_str(), W_OK) == 0;
                
                logDebug("get_file_info", "File info retrieved successfully",
                        {{"path", filepath}, {"size", info.size}, 
                         {"readable", info.is_readable}, {"writable", info.is_writable}});
            } else {
                logError("get_file_info", "Failed to get file info", 1015, {{"path", filepath}});
            }
            
            return info;
        }, {{"path", filepath}});
    }

    bool setPermissions(const string& filepath, bool readable, bool writable) {
        return measure("set_permissions", [&]() {
            mode_t mode = 0;
            if (readable) mode |= S_IRUSR | S_IRGRP | S_IROTH;
            if (writable) mode |= S_IWUSR | S_IWGRP | S_IWOTH;
            
            bool success = chmod(filepath.c_str(), mode) == 0;
            if (success) {
                logInfo("set_permissions", "File permissions updated successfully",
                       {{"path", filepath}, {"readable", readable}, {"writable", writable}});
            } else {
                logError("set_permissions", "Failed to set file permissions", 1016,
                        {{"path", filepath}, {"readable", readable}, {"writable", writable}});
            }
            return success;
        }, {{"path", filepath}, {"readable", readable}, {"writable", writable}});
    }

    string getChecksum(const string& filepath) {
        return measure("get_checksum", [&]() -> string {
            vector<uint8_t> data = readBinary(filepath);
            if (data.empty()) {
                logWarning("get_checksum", "File is empty or couldn't be read", {{"path", filepath}});
                return "";
            }
            
            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, data.data(), data.size());
            
            unsigned char digest[MD5_DIGEST_LENGTH];
            MD5_Final(digest, &context);
            
            char mdString[33];
            for (int i = 0; i < 16; i++)
                sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
            
            string checksum = string(mdString);
            logInfo("get_checksum", "File checksum calculated successfully",
                   {{"path", filepath}, {"checksum", checksum}});
            return checksum;
        }, {{"path", filepath}});
    }

    bool truncateFile(const string& filepath, uint64_t new_size) {
        return measure("truncate_file", [&]() {
            bool success = truncate(filepath.c_str(), static_cast<off_t>(new_size)) == 0;
            if (success) {
                logInfo("truncate_file", "File truncated successfully",
                       {{"path", filepath}, {"new_size", new_size}});
            } else {
                logError("truncate_file", "Failed to truncate file", 1017,
                        {{"path", filepath}, {"new_size", new_size}});
            }
            return success;
        }, {{"path", filepath}, {"new_size", new_size}});
    }

    bool clearFile(const string& filepath) {
        return measure("clear_file", [&]() {
            ofstream file(filepath, ios::trunc);
            if (!file.is_open()) {
                logError("clear_file", "Failed to open file for clearing", 1018, {{"path", filepath}});
                return false;
            }
            file.close();
            
            logInfo("clear_file", "File cleared successfully", {{"path", filepath}});
            return true;
        }, {{"path", filepath}});
    }

    bool compareFiles(const string& file1, const string& file2) {
        return measure("compare_files", [&]() {
            vector<uint8_t> data1 = readBinary(file1);
            vector<uint8_t> data2 = readBinary(file2);
            
            if (data1.size() != data2.size()) {
                logDebug("compare_files", "Files have different sizes",
                        {{"file1", file1}, {"file2", file2}, 
                         {"size1", data1.size()}, {"size2", data2.size()}});
                return false;
            }
            
            bool identical = memcmp(data1.data(), data2.data(), data1.size()) == 0;
            
            if (identical) {
                logInfo("compare_files", "Files are identical",
                       {{"file1", file1}, {"file2", file2}, {"size", data1.size()}});
            } else {
                logInfo("compare_files", "Files are different",
                       {{"file1", file1}, {"file2", file2}, {"size", data1.size()}});
            }
            
            return identical;
        }, {{"file1", file1}, {"file2", file2}});
    }

    string getExtension(const string& filepath) {
        size_t dot_pos = filepath.find_last_of('.');
        if (dot_pos == string::npos) return "";
        return filepath.substr(dot_pos + 1);
    }

    string getFilename(const string& filepath) {
        size_t slash_pos = filepath.find_last_of('/');
        if (slash_pos == string::npos) return filepath;
        return filepath.substr(slash_pos + 1);
    }

    bool openFile(const string& filepath, OpenMode mode, FILE*& file) {
        return measure("open_file", [&]() {
            const char* mode_str = "";
            switch (mode) {
                case OpenMode::Read: mode_str = "rb"; break;
                case OpenMode::Write: mode_str = "wb"; break;
                case OpenMode::Append: mode_str = "ab"; break;
                case OpenMode::ReadWrite: mode_str = "r+b"; break;
            }
            
            file = fopen(filepath.c_str(), mode_str);
            bool success = file != nullptr;
            
            if (success) {
                logDebug("open_file", "File opened successfully",
                        {{"path", filepath}, {"mode", mode_str}});
            } else {
                logError("open_file", "Failed to open file", 1019,
                        {{"path", filepath}, {"mode", mode_str}});
            }
            return success;
        }, {{"path", filepath}, {"mode", static_cast<int>(mode)}});
    }

    void closeFile(FILE* file) {
        if (file) {
            fclose(file);
            logDebug("close_file", "File closed successfully");
        }
    }

    string getTemporaryPath(const string& original_path) {
        return original_path + ".tmp";
    }
};