#pragma once
#include "metrics_engine.h"
#include <chrono>
#include <string>
#include <functional>

class MetricsBase {
protected:
    metrics::MetricsEngine& metrics_;
    std::string component_name_;
    bool metrics_enabled_;
    
    MetricsBase(const std::string& component_name, bool enabled = true) 
        : metrics_(metrics::MetricsEngine::getInstance())
        , component_name_(component_name)
        , metrics_enabled_(enabled) {
    }

public:
    virtual ~MetricsBase() = default;


    class ScopedTimer {
    private:
        MetricsBase& parent_;
        std::string operation_;
        std::chrono::high_resolution_clock::time_point start_;
        nlohmann::json custom_data_;
        bool success_ = true;
        std::function<void()> on_complete_;
        
    public:
        ScopedTimer(MetricsBase& parent, const std::string& operation, 
                   const nlohmann::json& data = {})
            : parent_(parent), operation_(operation), custom_data_(data) {
            start_ = std::chrono::high_resolution_clock::now();
        }
        

        void addData(const std::string& key, const nlohmann::json& value) {
            custom_data_[key] = value;
        }
        

        void setFailed(int error_code = 0, const std::string& error_msg = "") {
            success_ = false;
            if (!error_msg.empty()) {
                custom_data_["error_message"] = error_msg;
            }
            if (error_code != 0) {
                custom_data_["error_code"] = error_code;
            }
        }
        
        
        void setCompletionCallback(std::function<void()> callback) {
            on_complete_ = callback;
        }
        
        ~ScopedTimer() {
            if (!parent_.metrics_enabled_) return;
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_);
            
            if (success_) {
                parent_.metrics_.logOperation(parent_.component_name_, operation_, 
                                            true, duration.count(), custom_data_);
            } else {
                parent_.metrics_.logError(parent_.component_name_, operation_,
                                        "Operation failed", 
                                        custom_data_.value("error_code", 0),
                                        custom_data_);
            }
            
            if (on_complete_) {
                on_complete_();
            }
        }
    };


    template<typename Func, typename... Args>
    auto measure(const std::string& operation, Func&& func, 
                const nlohmann::json& context_data = {}, Args&&... args) {
        ScopedTimer timer(*this, operation, context_data);
        
        try {
            if constexpr (std::is_void_v<std::invoke_result_t<Func, Args...>>) {
                std::invoke(std::forward<Func>(func), std::forward<Args>(args)...);
            } else {
                auto result = std::invoke(std::forward<Func>(func), std::forward<Args>(args)...);
                return result;
            }
        } catch (const std::exception& e) {
            timer.setFailed(-1, e.what());
            throw;
        } catch (...) {
            timer.setFailed(-2, "Unknown exception");
            throw;
        }
    }


    void logDebug(const std::string& operation, const std::string& message,
                 const nlohmann::json& data = {}) {
        if (!metrics_enabled_) return;
        metrics_.logDebug(component_name_, operation, message, data);
    }
    
    void logInfo(const std::string& operation, const std::string& message,
                const nlohmann::json& data = {}) {
        if (!metrics_enabled_) return;
        metrics_.logInfo(component_name_, operation, message, data);
    }
    
    void logWarning(const std::string& operation, const std::string& message,
                   const nlohmann::json& data = {}) {
        if (!metrics_enabled_) return;
        metrics_.logWarning(component_name_, operation, message, data);
    }
    
    void logError(const std::string& operation, const std::string& message,
                 int error_code = 0, const nlohmann::json& data = {}) {
        if (!metrics_enabled_) return;
        metrics_.logError(component_name_, operation, message, error_code, data);
    }
    
    void logCritical(const std::string& operation, const std::string& message,
                    int error_code = 0, const nlohmann::json& data = {}) {
        if (!metrics_enabled_) return;
        metrics_.logCritical(component_name_, operation, message, error_code, data);
    }


    void logOperation(const std::string& operation, bool success, 
                     double duration_ms, const nlohmann::json& data = {}) {
        if (!metrics_enabled_) return;
        metrics_.logOperation(component_name_, operation, success, duration_ms, data);
    }


    void enableMetrics(bool enabled = true) { metrics_enabled_ = enabled; }
    void disableMetrics() { metrics_enabled_ = false; }
    bool isMetricsEnabled() const { return metrics_enabled_; }
    
    const std::string& getComponentName() const { return component_name_; }
    void setComponentName(const std::string& name) { component_name_ = name; }

    class BatchOperation {
    private:
        MetricsBase& parent_;
        std::string base_operation_;
        size_t total_items_ = 0;
        size_t processed_items_ = 0;
        size_t failed_items_ = 0;
        std::chrono::high_resolution_clock::time_point start_time_;
        
    public:
        BatchOperation(MetricsBase& parent, const std::string& operation, size_t total_items)
            : parent_(parent), base_operation_(operation), total_items_(total_items) {
            start_time_ = std::chrono::high_resolution_clock::now();
            parent_.logInfo(operation, "Batch operation started", 
                           {{"total_items", total_items}});
        }
        
        void itemProcessed(bool success = true) {
            processed_items_++;
            if (!success) failed_items_++;
        }
        
        void itemFailed() { failed_items_++; }
        
        ~BatchOperation() {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time_);
            
            bool overall_success = (failed_items_ == 0);
            parent_.logOperation(base_operation_, overall_success, duration.count(),
                               {{"total_items", total_items_},
                                {"processed_items", processed_items_},
                                {"failed_items", failed_items_},
                                {"success_rate", (processed_items_ > 0) ? 
                                    (1.0 - static_cast<double>(failed_items_) / processed_items_) : 1.0}});
        }
    };

    std::unique_ptr<BatchOperation> createBatchOperation(const std::string& operation, size_t total_items) {
        return std::make_unique<BatchOperation>(*this, operation, total_items);
    }

protected:
    template<typename T>
    void logIf(bool condition, const std::string& operation, const std::string& message,
               const T& data = {}) {
        if (condition && metrics_enabled_) {
            logInfo(operation, message, data);
        }
    }
};