#include "../include/tools/metrics_engine.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include <zlib.h>


namespace metrics {

MetricsEngine& MetricsEngine::getInstance() {
    static MetricsEngine instance;
    return instance;
}

MetricsEngine::MetricsEngine() 
    : initialized_(false)
    , total_metrics_(0)
    , batch_size_(100)
    , auto_flush_(true) {
}

MetricsEngine::~MetricsEngine() {
    shutdown();
}

bool MetricsEngine::initialize(const StorageConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return false;
    }
    
    config_ = config;
    storage_ = createStorage(config.format);
    
    if (!storage_->initialize(config)) {
        return false;
    }
    
    last_rotation_ = std::chrono::system_clock::now();
    initialized_ = true;
    
    return true;
}

bool MetricsEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    if (!batch_buffer_.empty()) {
        for (const auto& entry : batch_buffer_) {
            storage_->store(entry);
        }
        batch_buffer_.clear();
    }
    
    storage_->flush();
    initialized_ = false;
    
    return true;
}

void MetricsEngine::logDebug(const std::string& category, const std::string& operation,
                            const std::string& message, const nlohmann::json& data) {
    MetricEntry entry;
    entry.timestamp = getCurrentTimestamp();
    entry.level = LogLevel::DEBUG;
    entry.category = category;
    entry.operation = operation;
    entry.message = message;
    entry.data = data;
    entry.success = true;
    
    batchStore(entry);
}

void MetricsEngine::logInfo(const std::string& category, const std::string& operation,
                           const std::string& message, const nlohmann::json& data) {
    MetricEntry entry;
    entry.timestamp = getCurrentTimestamp();
    entry.level = LogLevel::INFO;
    entry.category = category;
    entry.operation = operation;
    entry.message = message;
    entry.data = data;
    entry.success = true;
    
    batchStore(entry);
}

void MetricsEngine::logWarning(const std::string& category, const std::string& operation,
                              const std::string& message, const nlohmann::json& data) {
    MetricEntry entry;
    entry.timestamp = getCurrentTimestamp();
    entry.level = LogLevel::WARNING;
    entry.category = category;
    entry.operation = operation;
    entry.message = message;
    entry.data = data;
    entry.success = false;
    
    batchStore(entry);
}

void MetricsEngine::logError(const std::string& category, const std::string& operation,
                            const std::string& message, int error_code, 
                            const nlohmann::json& data) {
    MetricEntry entry;
    entry.timestamp = getCurrentTimestamp();
    entry.level = LogLevel::ERROR;
    entry.category = category;
    entry.operation = operation;
    entry.message = message;
    entry.error_code = error_code;
    entry.data = data;
    entry.success = false;
    
    batchStore(entry);
}

void MetricsEngine::logCritical(const std::string& category, const std::string& operation,
                               const std::string& message, int error_code,
                               const nlohmann::json& data) {
    MetricEntry entry;
    entry.timestamp = getCurrentTimestamp();
    entry.level = LogLevel::CRITICAL;
    entry.category = category;
    entry.operation = operation;
    entry.message = message;
    entry.error_code = error_code;
    entry.data = data;
    entry.success = false;
    
    batchStore(entry);
}

void MetricsEngine::logOperation(const std::string& category, const std::string& operation,
                                bool success, double duration_ms, const nlohmann::json& data) {
    MetricEntry entry;
    entry.timestamp = getCurrentTimestamp();
    entry.level = success ? LogLevel::INFO : LogLevel::ERROR;
    entry.category = category;
    entry.operation = operation;
    entry.message = success ? "Operation completed successfully" : "Operation failed";
    entry.duration_ms = duration_ms;
    entry.data = data;
    entry.success = success;
    
    batchStore(entry);
}

bool MetricsEngine::setStorageFormat(StorageFormat format) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    if (config_.format == format) {
        return true;
    }
    
    config_.format = format;
    auto new_storage = createStorage(format);
    
    if (!new_storage->initialize(config_)) {
        return false;
    }
    
    storage_ = std::move(new_storage);
    return true;
}

bool MetricsEngine::setRotationPolicy(RotationPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    config_.rotation = policy;
    return true;
}

bool MetricsEngine::setMaxFileSize(uint64_t max_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return false;
    }
    
    config_.max_file_size = max_size;
    return true;
}

std::vector<MetricEntry> MetricsEngine::queryLogs(const std::string& category,
                                                 LogLevel min_level,
                                                 const std::string& start_time,
                                                 const std::string& end_time) {
    return {};
}

uint64_t MetricsEngine::getTotalMetricsCount() const {
    return total_metrics_.load();
}

std::map<std::string, uint64_t> MetricsEngine::getMetricsByCategory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return category_counts_;
}

std::map<LogLevel, uint64_t> MetricsEngine::getMetricsByLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_counts_;
}

bool MetricsEngine::exportMetrics(const std::string& filepath, StorageFormat format) {
    return false;
}

bool MetricsEngine::importMetrics(const std::string& filepath) {
    return false;
}

void MetricsEngine::setAutoFlush(bool enabled) {
    auto_flush_ = enabled;
}

void MetricsEngine::setBatchSize(uint32_t batch_size) {
    batch_size_ = batch_size;
}

std::string MetricsEngine::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    return ss.str();
}

std::string MetricsEngine::generateFilename() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    
    switch (config_.rotation) {
        case RotationPolicy::DAILY:
            ss << std::put_time(std::localtime(&time_t), "metrics_%Y-%m-%d");
            break;
        case RotationPolicy::HOURLY:
            ss << std::put_time(std::localtime(&time_t), "metrics_%Y-%m-%d_%H");
            break;
        case RotationPolicy::WEEKLY:
            ss << std::put_time(std::localtime(&time_t), "metrics_%Y-%W");
            break;
        case RotationPolicy::MONTHLY:
            ss << std::put_time(std::localtime(&time_t), "metrics_%Y-%m");
            break;
        default:
            ss << "metrics";
            break;
    }
    
    switch (config_.format) {
        case StorageFormat::TEXT: ss << ".log"; break;
        case StorageFormat::JSON: ss << ".json"; break;
        case StorageFormat::XML: ss << ".xml"; break;
        case StorageFormat::BINARY: ss << ".bin"; break;
    }
    
    return ss.str();
}

bool MetricsEngine::shouldRotate() {
    if (config_.rotation == RotationPolicy::MANUAL) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now();
    auto duration = now - last_rotation_;
    
    switch (config_.rotation) {
        case RotationPolicy::DAILY:
            return duration >= std::chrono::hours(24);
        case RotationPolicy::HOURLY:
            return duration >= std::chrono::hours(1);
        case RotationPolicy::WEEKLY:
            return duration >= std::chrono::hours(24 * 7);
        case RotationPolicy::MONTHLY:
            return duration >= std::chrono::hours(24 * 30);
        default:
            return false;
    }
}

void MetricsEngine::performRotation() {
    if (storage_) {
        storage_->rotate();
        last_rotation_ = std::chrono::system_clock::now();
    }
}

void MetricsEngine::batchStore(const MetricEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }
    
    if (shouldRotate()) {
        performRotation();
    }
    
    batch_buffer_.push_back(entry);
    
    total_metrics_++;
    category_counts_[entry.category]++;
    level_counts_[entry.level]++;
    
    if (auto_flush_ && batch_buffer_.size() >= batch_size_) {
        for (const auto& batch_entry : batch_buffer_) {
            storage_->store(batch_entry);
        }
        batch_buffer_.clear();
        storage_->flush();
    }
}

std::unique_ptr<MetricsStorage> MetricsEngine::createStorage(StorageFormat format) {
    switch (format) {
        case StorageFormat::TEXT:
            return std::make_unique<TextStorage>();
        case StorageFormat::JSON:
            return std::make_unique<JsonStorage>();
        case StorageFormat::BINARY:
            return std::make_unique<BinaryStorage>();
        default:
            return std::make_unique<TextStorage>();
    }
}

bool TextStorage::initialize(const StorageConfig& config) {
    config_ = config;
    
    std::filesystem::create_directories(config.base_path);
    current_file_ = config.base_path + "/" + 
                   std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".log";
    
    file_stream_.open(current_file_, std::ios::app);
    return file_stream_.is_open();
}

bool TextStorage::store(const MetricEntry& entry) {
    if (!file_stream_.is_open()) {
        return false;
    }
    
    file_stream_ << formatEntry(entry) << std::endl;
    
    if (config_.immediate_flush) {
        file_stream_.flush();
    }
    
    return true;
}

bool TextStorage::flush() {
    if (file_stream_.is_open()) {
        file_stream_.flush();
    }
    return true;
}

bool TextStorage::rotate() {
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
    
    current_file_ = config_.base_path + "/" + 
                   std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".log";
    
    file_stream_.open(current_file_, std::ios::app);
    return file_stream_.is_open();
}

std::vector<std::string> TextStorage::getAvailableLogs() {
    std::vector<std::string> logs;
    
    for (const auto& entry : std::filesystem::directory_iterator(config_.base_path)) {
        if (entry.is_regular_file() && entry.path().extension() == ".log") {
            logs.push_back(entry.path().string());
        }
    }
    
    return logs;
}

bool TextStorage::cleanup() {
    auto logs = getAvailableLogs();
    
    if (logs.size() > config_.max_files) {
        std::sort(logs.begin(), logs.end());
        
        for (size_t i = 0; i < logs.size() - config_.max_files; i++) {
            std::filesystem::remove(logs[i]);
        }
    }
    
    return true;
}

std::string TextStorage::formatEntry(const MetricEntry& entry) {
    std::stringstream ss;
    ss << "[" << entry.timestamp << "] "
       << "[" << getLevelString(entry.level) << "] "
       << "[" << entry.category << "] "
       << "[" << entry.operation << "] "
       << entry.message;
       
    if (entry.error_code != 0) {
        ss << " (Error: " << entry.error_code << ")";
    }
    
    if (entry.duration_ms > 0) {
        ss << " [Duration: " << entry.duration_ms << "ms]";
    }
    
    if (!entry.data.empty()) {
        ss << " [Data: " << entry.data.dump() << "]";
    }
    
    return ss.str();
}

std::string TextStorage::getLevelString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

bool JsonStorage::initialize(const StorageConfig& config) {
    config_ = config;
    
    std::filesystem::create_directories(config.base_path);
    current_file_ = config.base_path + "/" + 
                   std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".json";
    
    file_stream_.open(current_file_, std::ios::app);
    
    if (file_stream_.is_open()) {
        current_batch_ = nlohmann::json::array();
        return true;
    }
    
    return false;
}

bool JsonStorage::store(const MetricEntry& entry) {
    if (!file_stream_.is_open()) {
        return false;
    }
    
    current_batch_.push_back(convertToJson(entry));
    
    if (config_.immediate_flush) {
        return flush();
    }
    
    return true;
}

bool JsonStorage::flush() {
    if (!file_stream_.is_open() || current_batch_.empty()) {
        return true;
    }
    
    file_stream_ << current_batch_.dump(2) << std::endl;
    file_stream_.flush();
    
    current_batch_.clear();
    return true;
}

bool JsonStorage::rotate() {
    flush();
    
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
    
    current_file_ = config_.base_path + "/" + 
                   std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".json";
    
    file_stream_.open(current_file_, std::ios::app);
    
    if (file_stream_.is_open()) {
        current_batch_ = nlohmann::json::array();
        return true;
    }
    
    return false;
}

std::vector<std::string> JsonStorage::getAvailableLogs() {
    std::vector<std::string> logs;
    
    for (const auto& entry : std::filesystem::directory_iterator(config_.base_path)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            logs.push_back(entry.path().string());
        }
    }
    
    return logs;
}

bool JsonStorage::cleanup() {
    auto logs = getAvailableLogs();
    
    if (logs.size() > config_.max_files) {
        std::sort(logs.begin(), logs.end());
        
        for (size_t i = 0; i < logs.size() - config_.max_files; i++) {
            std::filesystem::remove(logs[i]);
        }
    }
    
    return true;
}

nlohmann::json JsonStorage::convertToJson(const MetricEntry& entry) {
    nlohmann::json j;
    j["timestamp"] = entry.timestamp;
    j["level"] = static_cast<int>(entry.level);
    j["category"] = entry.category;
    j["operation"] = entry.operation;
    j["message"] = entry.message;
    j["data"] = entry.data;
    j["error_code"] = entry.error_code;
    j["duration_ms"] = entry.duration_ms;
    j["success"] = entry.success;
    
    return j;
}

bool BinaryStorage::initialize(const StorageConfig& config) {
    config_ = config;
    
    std::filesystem::create_directories(config.base_path);
    current_file_ = config.base_path + "/" + 
                   std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".bin";
    
    file_stream_.open(current_file_, std::ios::binary | std::ios::app);
    return file_stream_.is_open();
}

bool BinaryStorage::store(const MetricEntry& entry) {
    binary_buffer_.push_back(entry);
    
    if (config_.immediate_flush || binary_buffer_.size() >= 100) {
        return flush();
    }
    
    return true;
}

bool BinaryStorage::flush() {
    if (!file_stream_.is_open() || binary_buffer_.empty()) {
        return true;
    }
    
    for (const auto& entry : binary_buffer_) {
        std::string timestamp = entry.timestamp;
        std::string category = entry.category;
        std::string operation = entry.operation;
        std::string message = entry.message;
        std::string data_str = entry.data.dump();
        
        uint32_t timestamp_len = timestamp.length();
        uint32_t category_len = category.length();
        uint32_t operation_len = operation.length();
        uint32_t message_len = message.length();
        uint32_t data_len = data_str.length();
        
        file_stream_.write(reinterpret_cast<const char*>(&timestamp_len), sizeof(timestamp_len));
        file_stream_.write(timestamp.c_str(), timestamp_len);
        
        file_stream_.write(reinterpret_cast<const char*>(&category_len), sizeof(category_len));
        file_stream_.write(category.c_str(), category_len);
        
        file_stream_.write(reinterpret_cast<const char*>(&operation_len), sizeof(operation_len));
        file_stream_.write(operation.c_str(), operation_len);
        
        file_stream_.write(reinterpret_cast<const char*>(&message_len), sizeof(message_len));
        file_stream_.write(message.c_str(), message_len);
        
        file_stream_.write(reinterpret_cast<const char*>(&data_len), sizeof(data_len));
        file_stream_.write(data_str.c_str(), data_len);
        
        file_stream_.write(reinterpret_cast<const char*>(&entry.level), sizeof(entry.level));
        file_stream_.write(reinterpret_cast<const char*>(&entry.error_code), sizeof(entry.error_code));
        file_stream_.write(reinterpret_cast<const char*>(&entry.duration_ms), sizeof(entry.duration_ms));
        file_stream_.write(reinterpret_cast<const char*>(&entry.success), sizeof(entry.success));
    }
    
    file_stream_.flush();
    binary_buffer_.clear();
    
    return true;
}

bool BinaryStorage::rotate() {
    flush();
    
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
    
    current_file_ = config_.base_path + "/" + 
                   std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ".bin";
    
    file_stream_.open(current_file_, std::ios::binary | std::ios::app);
    return file_stream_.is_open();
}

std::vector<std::string> BinaryStorage::getAvailableLogs() {
    std::vector<std::string> logs;
    
    for (const auto& entry : std::filesystem::directory_iterator(config_.base_path)) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            logs.push_back(entry.path().string());
        }
    }
    
    return logs;
}

bool BinaryStorage::cleanup() {
    auto logs = getAvailableLogs();
    
    if (logs.size() > config_.max_files) {
        std::sort(logs.begin(), logs.end());
        
        for (size_t i = 0; i < logs.size() - config_.max_files; i++) {
            std::filesystem::remove(logs[i]);
        }
    }
    
    return true;
}
}