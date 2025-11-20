#ifndef METRICS_ENGINE_H
#define METRICS_ENGINE_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>
#include <nlohmann/json.hpp>

namespace metrics {
    enum class LogLevel {
        DEBUG,
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };

    enum class StorageFormat {
        TEXT,
        JSON,
        XML,
        BINARY
    };

    enum class RotationPolicy {
        DAILY,
        HOURLY,
        WEEKLY,
        MONTHLY,
        SIZE_BASED,
        MANUAL
    };

    struct MetricEntry {
        std::string timestamp;
        LogLevel level;
        std::string category;
        std::string operation;
        std::string message;
        nlohmann::json data;
        int error_code;
        double duration_ms;
        bool success;
    };

    struct StorageConfig {
        std::string base_path;
        StorageFormat format;
        RotationPolicy rotation;
        uint64_t max_file_size;
        uint32_t max_files;
        bool compress_old_files;
        bool immediate_flush;
    };

    class MetricsStorage {
    public:
        virtual ~MetricsStorage() = default;
        virtual bool initialize(const StorageConfig& config) = 0;
        virtual bool store(const MetricEntry& entry) = 0;
        virtual bool flush() = 0;
        virtual bool rotate() = 0;
        virtual std::vector<std::string> getAvailableLogs() = 0;
        virtual bool cleanup() = 0;
    };

    class MetricsEngine {
    public:
        static MetricsEngine& getInstance();
        
        bool initialize(const StorageConfig& config);
        bool shutdown();
        
        void logDebug(const std::string& category, const std::string& operation, 
                     const std::string& message, const nlohmann::json& data = {});
        void logInfo(const std::string& category, const std::string& operation,
                    const std::string& message, const nlohmann::json& data = {});
        void logWarning(const std::string& category, const std::string& operation,
                       const std::string& message, const nlohmann::json& data = {});
        void logError(const std::string& category, const std::string& operation,
                     const std::string& message, int error_code = 0, 
                     const nlohmann::json& data = {});
        void logCritical(const std::string& category, const std::string& operation,
                        const std::string& message, int error_code = 0,
                        const nlohmann::json& data = {});
        
        void logOperation(const std::string& category, const std::string& operation,
                         bool success, double duration_ms, const nlohmann::json& data = {});
        
        bool setStorageFormat(StorageFormat format);
        bool setRotationPolicy(RotationPolicy policy);
        bool setMaxFileSize(uint64_t max_size);
        
        std::vector<MetricEntry> queryLogs(const std::string& category = "",
                                          LogLevel min_level = LogLevel::DEBUG,
                                          const std::string& start_time = "",
                                          const std::string& end_time = "");
        
        uint64_t getTotalMetricsCount() const;
        std::map<std::string, uint64_t> getMetricsByCategory() const;
        std::map<LogLevel, uint64_t> getMetricsByLevel() const;
        
        bool exportMetrics(const std::string& filepath, StorageFormat format);
        bool importMetrics(const std::string& filepath);
        
        void setAutoFlush(bool enabled);
        void setBatchSize(uint32_t batch_size);

    private:
        MetricsEngine();
        ~MetricsEngine();
        
        std::string getCurrentTimestamp();
        std::string generateFilename();
        bool shouldRotate();
        void performRotation();
        void batchStore(const MetricEntry& entry);
        
        std::unique_ptr<MetricsStorage> createStorage(StorageFormat format);
        
        std::unique_ptr<MetricsStorage> storage_;
        StorageConfig config_;
        std::atomic<bool> initialized_;
        std::atomic<uint64_t> total_metrics_;
        std::map<std::string, uint64_t> category_counts_;
        std::map<LogLevel, uint64_t> level_counts_;
        
        std::vector<MetricEntry> batch_buffer_;
        std::atomic<uint32_t> batch_size_;
        std::atomic<bool> auto_flush_;
        std::chrono::system_clock::time_point last_rotation_;
        
        mutable std::mutex mutex_;
    };

    class TextStorage : public MetricsStorage {
    public:
        bool initialize(const StorageConfig& config) override;
        bool store(const MetricEntry& entry) override;
        bool flush() override;
        bool rotate() override;
        std::vector<std::string> getAvailableLogs() override;
        bool cleanup() override;

    private:
        std::string formatEntry(const MetricEntry& entry);
        std::string getLevelString(LogLevel level);
        
        std::string current_file_;
        StorageConfig config_;
        std::ofstream file_stream_;
    };

    class JsonStorage : public MetricsStorage {
    public:
        bool initialize(const StorageConfig& config) override;
        bool store(const MetricEntry& entry) override;
        bool flush() override;
        bool rotate() override;
        std::vector<std::string> getAvailableLogs() override;
        bool cleanup() override;

    private:
        nlohmann::json convertToJson(const MetricEntry& entry);
        
        std::string current_file_;
        StorageConfig config_;
        std::ofstream file_stream_;
        nlohmann::json current_batch_;
    };

    class BinaryStorage : public MetricsStorage {
    public:
        bool initialize(const StorageConfig& config) override;
        bool store(const MetricEntry& entry) override;
        bool flush() override;
        bool rotate() override;
        std::vector<std::string> getAvailableLogs() override;
        bool cleanup() override;

    private:
        struct BinaryHeader {
            char magic[4];
            uint32_t version;
            uint64_t entry_count;
        };
        
        std::string current_file_;
        StorageConfig config_;
        std::ofstream file_stream_;
        std::vector<MetricEntry> binary_buffer_;
    };
}

#endif