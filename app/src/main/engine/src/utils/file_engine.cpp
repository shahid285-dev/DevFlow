#include "../include/tools/file_engine.h"
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/md5.h>


using namespace std;


bool FileEngine::createFile(const string& filepath) {
    if (filepath.empty()) return false;
    
    ofstream file(filepath);
    if (!file.is_open()) return false;
    
    file.close();
    return true;
}

bool FileEngine::deleteFile(const string& filepath) {
    if (!exists(filepath)) return false;
    return remove(filepath.c_str()) == 0;
}

bool FileEngine::renameFile(const string& old_path, const string& new_path) {
    if (!exists(old_path) || new_path.empty()) return false;
    return rename(old_path.c_str(), new_path.c_str()) == 0;
}

bool FileEngine::copyFile(const string& source_path, const string& dest_path) {
    if (!exists(source_path) || dest_path.empty()) return false;
    
    ifstream source(source_path, ios::binary);
    ofstream dest(dest_path, ios::binary);
    
    if (!source.is_open() || !dest.is_open()) return false;
    
    dest << source.rdbuf();
    
    source.close();
    dest.close();
    return true;
}

bool FileEngine::exists(const string& filepath) {
    struct stat buffer;
    return stat(filepath.c_str(), &buffer) == 0;
}

bool FileEngine::writeText(const string& filepath, const string& content) {
    ofstream file(filepath);
    if (!file.is_open()) return false;
    
    file << content;
    file.close();
    return true;
}

bool FileEngine::writeBinary(const string& filepath, const vector<uint8_t>& data) {
    ofstream file(filepath, ios::binary);
    if (!file.is_open()) return false;
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

bool FileEngine::appendText(const string& filepath, const string& content) {
    ofstream file(filepath, ios::app);
    if (!file.is_open()) return false;
    
    file << content;
    file.close();
    return true;
}

bool FileEngine::appendBinary(const string& filepath, const vector<uint8_t>& data) {
    ofstream file(filepath, ios::binary | ios::app);
    if (!file.is_open()) return false;
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

string FileEngine::readText(const string& filepath) {
    ifstream file(filepath);
    if (!file.is_open()) return "";
    
    stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    
    return buffer.str();
}

vector<uint8_t> FileEngine::readBinary(const string& filepath) {
    ifstream file(filepath, ios::binary | ios::ate);
    if (!file.is_open()) return {};
    
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    
    vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    file.close();
    
    return buffer;
}

vector<string> FileEngine::readLines(const string& filepath) {
    vector<string> lines;
    ifstream file(filepath);
    
    if (!file.is_open()) return lines;
    
    string line;
    while (getline(file, line)) {
        lines.push_back(line);
    }
    
    file.close();
    return lines;
}

bool FileEngine::updateContent(const string& filepath, const string& new_content) {
    return writeText(filepath, new_content);
}

bool FileEngine::replaceInFile(const string& filepath, const string& search, const string& replace) {
    string content = readText(filepath);
    if (content.empty() && !exists(filepath)) return false;
    
    size_t pos = 0;
    while ((pos = content.find(search, pos)) != string::npos) {
        content.replace(pos, search.length(), replace);
        pos += replace.length();
    }
    
    return writeText(filepath, content);
}

uint64_t FileEngine::getFileSize(const string& filepath) {
    struct stat stat_buf;
    if (stat(filepath.c_str(), &stat_buf) != 0) return 0;
    return static_cast<uint64_t>(stat_buf.st_size);
}

time_t FileEngine::getLastModifiedTime(const string& filepath) {
    struct stat stat_buf;
    if (stat(filepath.c_str(), &stat_buf) != 0) return 0;
    return stat_buf.st_mtime;
}

FileEngine::FileInfo FileEngine::getFileInfo(const string& filepath) {
    FileInfo info;
    info.path = filepath;
    info.filename = getFilename(filepath);
    
    struct stat stat_buf;
    if (stat(filepath.c_str(), &stat_buf) == 0) {
        info.size = static_cast<uint64_t>(stat_buf.st_size);
        info.last_modified = stat_buf.st_mtime;
        info.is_readable = access(filepath.c_str(), R_OK) == 0;
        info.is_writable = access(filepath.c_str(), W_OK) == 0;
    }
    
    return info;
}

bool FileEngine::setPermissions(const string& filepath, bool readable, bool writable) {
    mode_t mode = 0;
    if (readable) mode |= S_IRUSR | S_IRGRP | S_IROTH;
    if (writable) mode |= S_IWUSR | S_IWGRP | S_IWOTH;
    
    return chmod(filepath.c_str(), mode) == 0;
}

string FileEngine::getChecksum(const string& filepath) {
    vector<uint8_t> data = readBinary(filepath);
    if (data.empty()) return "";
    
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, data.data(), data.size());
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &context);
    
    char mdString[33];
    for (int i = 0; i < 16; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    
    return string(mdString);
}

bool FileEngine::truncateFile(const string& filepath, uint64_t new_size) {
    return truncate(filepath.c_str(), static_cast<off_t>(new_size)) == 0;
}

bool FileEngine::clearFile(const string& filepath) {
    ofstream file(filepath, ios::trunc);
    if (!file.is_open()) return false;
    file.close();
    return true;
}

bool FileEngine::compareFiles(const string& file1, const string& file2) {
    vector<uint8_t> data1 = readBinary(file1);
    vector<uint8_t> data2 = readBinary(file2);
    
    if (data1.size() != data2.size()) return false;
    
    return memcmp(data1.data(), data2.data(), data1.size()) == 0;
}

string FileEngine::getExtension(const string& filepath) {
    size_t dot_pos = filepath.find_last_of('.');
    if (dot_pos == string::npos) return "";
    return filepath.substr(dot_pos + 1);
}

string FileEngine::getFilename(const string& filepath) {
    size_t slash_pos = filepath.find_last_of('/');
    if (slash_pos == string::npos) return filepath;
    return filepath.substr(slash_pos + 1);
}

bool FileEngine::openFile(const string& filepath, OpenMode mode, FILE*& file) {
    const char* mode_str = "";
    switch (mode) {
        case OpenMode::Read: mode_str = "rb"; break;
        case OpenMode::Write: mode_str = "wb"; break;
        case OpenMode::Append: mode_str = "ab"; break;
        case OpenMode::ReadWrite: mode_str = "r+b"; break;
    }
    
    file = fopen(filepath.c_str(), mode_str);
    return file != nullptr;
}

void FileEngine::closeFile(FILE* file) {
    if (file) fclose(file);
}

string FileEngine::getTemporaryPath(const string& original_path) {
    return original_path + ".tmp";
}