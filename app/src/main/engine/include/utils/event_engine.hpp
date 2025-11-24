#ifndef EVENT_ENGINE_H
#define EVENT_ENGINE_H

#include <memory>
#include <unordered_map>
#include <vector>
#include <functional>
#include <typeindex>
#include <mutex>
#include <atomic>
#include <deque>
#include <future>
#include <thread>
#include <condition_variable>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <sstream>

namespace EventSystem {

// ----------------- Logger interfaces -----------------
class ILogger {
public:
    virtual ~ILogger() = default;
    enum class Level { Debug, Info, Warning, Error, Critical };

    // Logger must not throw; wrapper in engine will catch exceptions.
    virtual void log(Level level, const std::string& message) noexcept = 0;
};

class ConsoleLogger : public ILogger {
public:
    void log(Level level, const std::string& message) noexcept override {
        try {
            const char* level_str[] = {"DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"};
            std::cerr << "[" << level_str[static_cast<int>(level)] << "] "
                      << message << std::endl;
        } catch (...) {
            // swallow
        }
    }
};

class NullLogger : public ILogger {
public:
    void log(Level, const std::string&) noexcept override {}
};

// ----------------- Events & handlers -----------------
class IEvent {
public:
    virtual ~IEvent() = default;
    virtual std::type_index get_type() const = 0;
};

template<typename PayloadType>
class Event : public IEvent {
public:
    using payload_type = PayloadType;

    template<typename... Args>
    explicit Event(Args&&... args)
        : payload_(std::forward<Args>(args)...) {}

    std::type_index get_type() const override {
        return std::type_index(typeid(Event<PayloadType>));
    }

    const PayloadType& payload() const { return payload_; }
    PayloadType& payload() { return payload_; }

private:
    PayloadType payload_;
};

class IEventHandler {
public:
    virtual ~IEventHandler() = default;
    virtual void handle_event(const std::shared_ptr<IEvent>& event) = 0;
    virtual std::type_index get_event_type() const = 0;
    virtual std::weak_ptr<void> get_owner() const = 0;
    virtual bool try_handle_event(const std::shared_ptr<IEvent>& event) = 0;
    virtual void deactivate() = 0;
    virtual void mark_removed() = 0;
    virtual uint64_t get_subscription_id() const = 0;
    virtual bool is_removed() const = 0;
};

template<typename EventType, typename HandlerClass>
class EventHandler : public IEventHandler {
public:
    using HandlerFunction = void (HandlerClass::*)(const typename EventType::payload_type&);

    EventHandler(std::shared_ptr<HandlerClass> instance,
                 HandlerFunction function,
                 uint64_t subscription_id)
        : instance_(instance),
          function_(function),
          active_(true),
          removed_(std::make_shared<std::atomic<bool>>(false)),
          subscription_id_(subscription_id) {
        if (!instance) {
            throw std::invalid_argument("EventHandler: instance cannot be null");
        }
        if (!function) {
            throw std::invalid_argument("EventHandler: function cannot be null");
        }
    }

    void handle_event(const std::shared_ptr<IEvent>& event) override {
        if (!active_.load(std::memory_order_acquire) || is_removed()) return;

        auto owner = instance_.lock();
        if (!owner) {
            deactivate();
            return;
        }

        if (auto derived_event = std::dynamic_pointer_cast<EventType>(event)) {
            if (active_.load(std::memory_order_acquire) && !is_removed()) {
                ((*owner).*function_)(derived_event->payload());
            }
        }
    }

    bool try_handle_event(const std::shared_ptr<IEvent>& event) override {
        if (!active_.load(std::memory_order_acquire) || is_removed()) return false;

        auto owner = instance_.lock();
        if (!owner) {
            deactivate();
            return false;
        }

        if (auto derived_event = std::dynamic_pointer_cast<EventType>(event)) {
            if (active_.load(std::memory_order_acquire) && !is_removed()) {
                ((*owner).*function_)(derived_event->payload());
                return true;
            }
        }
        return false;
    }

    std::type_index get_event_type() const override {
        return std::type_index(typeid(EventType));
    }

    std::weak_ptr<void> get_owner() const override {
        return instance_;
    }

    void deactivate() override {
        active_.store(false, std::memory_order_release);
    }

    void mark_removed() override {
        removed_->store(true, std::memory_order_release);
    }

    bool is_removed() const override {
        return removed_->load(std::memory_order_acquire);
    }

    uint64_t get_subscription_id() const override {
        return subscription_id_;
    }

private:
    std::weak_ptr<HandlerClass> instance_;
    HandlerFunction function_;
    std::atomic<bool> active_;
    std::shared_ptr<std::atomic<bool>> removed_;
    uint64_t subscription_id_;
};

// ----------------- Exceptions -----------------
class EventEngineException : public std::runtime_error {
public:
    explicit EventEngineException(const std::string& message)
        : std::runtime_error(message) {}
};

class MaxHandlersExceededException : public EventEngineException {
public:
    MaxHandlersExceededException()
        : EventEngineException("Maximum handler count exceeded") {}
};

class HandlerIdExhaustedException : public EventEngineException {
public:
    HandlerIdExhaustedException()
        : EventEngineException("Handler ID space exhausted") {}
};

class InvalidArgumentException : public EventEngineException {
public:
    explicit InvalidArgumentException(const std::string& message)
        : EventEngineException("Invalid argument: " + message) {}
};

// ----------------- Dispatcher -----------------
using HandlerId = uint64_t;

class EventDispatcher {
public:
    // sensible defaults and hard limits
    static constexpr size_t DEFAULT_MAX_QUEUE_SIZE = 1000;
    static constexpr size_t DEFAULT_MAX_HANDLERS = 10000;
    static constexpr size_t ABSOLUTE_MAX_HANDLERS = 1000000;
    static constexpr size_t ABSOLUTE_MAX_QUEUE = 100000;
    static constexpr size_t CLEANUP_THRESHOLD = 1000;
    static constexpr size_t ID_RESERVE = 1000;

    explicit EventDispatcher(std::shared_ptr<ILogger> logger = nullptr);
    ~EventDispatcher() noexcept;

    // -- templates (implemented inline so header-only instantiation works) --
    template<typename EventType, typename HandlerClass>
    HandlerId subscribe(std::shared_ptr<HandlerClass> handler,
                       typename EventHandler<EventType, HandlerClass>::HandlerFunction function);

    template<typename EventType, typename Function>
    HandlerId subscribe(Function&& function);

    bool unsubscribe(HandlerId id) noexcept;

    template<typename EventType>
    void unsubscribe_all() noexcept;

    template<typename EventType, typename... Args>
    void dispatch(Args&&... args) noexcept;

    template<typename EventType, typename... Args>
    std::future<void> dispatch_async(Args&&... args);

    // runtime configuration
    void set_max_queue_size(size_t size);
    void set_max_handlers(size_t max_handlers);
    void set_handler_timeout(std::chrono::milliseconds timeout);
    void set_logger(std::shared_ptr<ILogger> logger);

    // control
    void start_processing() noexcept;
    void stop_processing() noexcept;
    bool wait_until_empty(std::chrono::milliseconds timeout) const;

    // introspection
    size_t get_pending_events() const noexcept;
    size_t get_handler_count() const noexcept;
    void clear_pending_events() noexcept;
    void force_cleanup() noexcept;

    enum class DispatchResult {
        Success,
        QueueFull,
        DispatcherStopped,
        NoHandlers,
        HandlerException,
        MaxHandlersExceeded,
        InvalidState
    };

    using ExceptionCallback = std::function<void(HandlerId handler_id, const std::exception& e)>;
    void set_exception_callback(ExceptionCallback callback);

private:
    // internal helpers
    void process_events() noexcept;
    void cleanup_inactive_handlers() noexcept;
    HandlerId generate_handler_id_unsafe();
    bool can_process_events() const noexcept;
    void safe_promise_set(std::promise<void>& promise) noexcept;
    void safe_promise_set_exception(std::promise<void>& promise, const std::exception_ptr& exc) noexcept;
    void drain_queue_on_stop() noexcept;
    void safe_execution_flag_reset(const std::vector<std::shared_ptr<std::atomic<bool>>>& execution_flags) noexcept;
    void log_message(ILogger::Level level, const std::string& message) noexcept;
    void invoke_exception_callback(HandlerId handler_id, const std::exception& e) noexcept;
    void decrement_handler_count_safe() noexcept;

    // Handler entry in the handler map
    struct HandlerEntry {
        HandlerId id;
        std::shared_ptr<IEventHandler> handler;
        std::shared_ptr<std::atomic<bool>> pending_execution{std::make_shared<std::atomic<bool>>(false)};
        std::shared_ptr<std::atomic<bool>> removed{std::make_shared<std::atomic<bool>>(false)};
        bool counted{true}; // indicates whether total_handler_count_ already accounts this entry
    };

    // Event wrapper stored in the queue; stored via shared_ptr in queue to ensure stable addresses
    struct EventWrapper {
        std::shared_ptr<IEvent> event;
        std::shared_ptr<std::promise<void>> promise;
        std::shared_ptr<std::atomic<bool>> promise_set{std::make_shared<std::atomic<bool>>(false)};

        EventWrapper() = default;
        EventWrapper(std::shared_ptr<IEvent> e, std::shared_ptr<std::promise<void>> p)
            : event(std::move(e)), promise(std::move(p)), promise_set(std::make_shared<std::atomic<bool>>(false)) {}
    };

    // core data structures
    std::unordered_map<std::type_index, std::vector<HandlerEntry>> handlers_;
    mutable std::mutex handlers_mutex_;

    std::atomic<size_t> total_handler_count_{0};
    size_t max_handlers_{DEFAULT_MAX_HANDLERS};
    std::chrono::milliseconds handler_timeout_{0};

    // use shared_ptr<EventWrapper> in the queue to avoid pointer/iterator invalidation
    std::deque<std::shared_ptr<EventWrapper>> event_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::condition_variable stop_condition_;
    size_t max_queue_size_{DEFAULT_MAX_QUEUE_SIZE};

    std::atomic<bool> processing_{false};
    std::atomic<bool> destruction_flag_{false};
    std::atomic<bool> drain_mode_{false};
    std::atomic<HandlerId> next_handler_id_{1};
    std::thread worker_thread_;

    std::atomic<size_t> cleanup_counter_{0};

    // constants (also defined above as static constexpr)
    // logging & callbacks
    std::shared_ptr<ILogger> logger_;
    ExceptionCallback exception_callback_;
    std::mutex callback_mutex_;

    // single mutex to serialize thread start/stop or other global-order ops
    mutable std::mutex control_mutex_;
};

// ----------------- ScopedSubscription -----------------
class ScopedSubscription {
public:
    ScopedSubscription() = default;
    ScopedSubscription(EventDispatcher* dispatcher, HandlerId id);

    ~ScopedSubscription() noexcept;

    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;

    ScopedSubscription(ScopedSubscription&& other) noexcept;
    ScopedSubscription& operator=(ScopedSubscription&& other) noexcept;

    explicit operator bool() const { return dispatcher_ != nullptr && id_ != 0; }

    bool unsubscribe() noexcept;
    bool is_valid() const { return dispatcher_ != nullptr && id_ != 0; }

private:
    EventDispatcher* dispatcher_{nullptr};
    HandlerId id_{0};
};

// ----------------- EventChannel (inline templates) -----------------
template<typename PayloadType>
class EventChannel {
public:
    explicit EventChannel(EventDispatcher& dispatcher) : dispatcher_(dispatcher) {}

    template<typename... Args>
    void publish(Args&&... args) {
        dispatcher_.dispatch<Event<PayloadType>>(std::forward<Args>(args)...);
    }

    template<typename... Args>
    std::future<void> publish_async(Args&&... args) {
        return dispatcher_.dispatch_async<Event<PayloadType>>(std::forward<Args>(args)...);
    }

    template<typename HandlerClass>
    ScopedSubscription subscribe(std::shared_ptr<HandlerClass> handler,
                                void (HandlerClass::*function)(const PayloadType&)) {
        auto id = dispatcher_.subscribe<Event<PayloadType>>(handler, function);
        return ScopedSubscription(&dispatcher_, id);
    }

    template<typename Function>
    ScopedSubscription subscribe(Function&& function) {
        auto id = dispatcher_.subscribe<Event<PayloadType>>(std::forward<Function>(function));
        return ScopedSubscription(&dispatcher_, id);
    }

private:
    EventDispatcher& dispatcher_;
};

// ----------------- Template definitions for EventDispatcher -----------------
// NOTE: These are implemented here so that template instantiations are available
// at compile/link time for any EventType the user uses.

template<typename EventType, typename HandlerClass>
HandlerId EventDispatcher::subscribe(std::shared_ptr<HandlerClass> handler,
                                     typename EventHandler<EventType, HandlerClass>::HandlerFunction function) {
    if (!handler) {
        throw InvalidArgumentException("handler cannot be null");
    }
    if (!function) {
        throw InvalidArgumentException("handler function cannot be null");
    }
    if (destruction_flag_.load(std::memory_order_acquire)) {
        throw EventEngineException("Cannot subscribe during destruction");
    }

    std::lock_guard<std::mutex> lock(handlers_mutex_);

    if (total_handler_count_.load(std::memory_order_acquire) >= max_handlers_) {
        throw MaxHandlersExceededException();
    }

    // create handler object first (no id yet)
    HandlerId id = generate_handler_id_unsafe();
    auto handler_ptr = std::make_shared<EventHandler<EventType, HandlerClass>>(handler, function, id);

    HandlerEntry entry;
    entry.id = id;
    entry.handler = handler_ptr;
    entry.pending_execution = std::make_shared<std::atomic<bool>>(false);
    entry.removed = std::make_shared<std::atomic<bool>>(false);
    entry.counted = true;

    handlers_[std::type_index(typeid(EventType))].push_back(std::move(entry));
    total_handler_count_.fetch_add(1, std::memory_order_acq_rel);

    // log outside of locked regions by scheduling message (caller can log)
    if (logger_) {
        try {
            logger_->log(ILogger::Level::Debug, "Handler subscribed with ID: " + std::to_string(id));
        } catch (...) {}
    }

    return id;
}

template<typename EventType, typename Function>
HandlerId EventDispatcher::subscribe(Function&& function) {
    if (destruction_flag_.load(std::memory_order_acquire)) {
        throw EventEngineException("Cannot subscribe during destruction");
    }

    std::lock_guard<std::mutex> lock(handlers_mutex_);

    if (total_handler_count_.load(std::memory_order_acquire) >= max_handlers_) {
        throw MaxHandlersExceededException();
    }

    // create wrapper for lambda handler
    struct FunctionWrapper {
        std::function<void(const typename EventType::payload_type&)> function;
        ExceptionCallback exception_callback;
        std::shared_ptr<ILogger> logger;
        uint64_t subscription_id;
        std::mutex callback_lock;

        FunctionWrapper(std::function<void(const typename EventType::payload_type&)> f,
                        uint64_t id,
                        std::shared_ptr<ILogger> l,
                        ExceptionCallback cb)
            : function(std::move(f)), exception_callback(cb), logger(std::move(l)), subscription_id(id) {
            if (!function) throw InvalidArgumentException("function cannot be null");
        }

        bool try_execute(const typename EventType::payload_type& payload) {
            try {
                function(payload);
                return true;
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lk(callback_lock);
                if (exception_callback) {
                    try { exception_callback(subscription_id, e); } catch (...) {}
                }
                if (logger) {
                    try { logger->log(ILogger::Level::Error, std::string("Lambda handler exception: ") + e.what()); } catch(...) {}
                }
                return false;
            } catch (...) {
                if (logger) {
                    try { logger->log(ILogger::Level::Error, "Lambda handler unknown exception"); } catch(...) {}
                }
                return false;
            }
        }
    };

    // Generate id and create event handler wrapper
    HandlerId id = generate_handler_id_unsafe();
    auto wrapper = std::make_shared<FunctionWrapper>(std::forward<Function>(function), id, logger_, exception_callback_);

    class FunctionEventHandler : public IEventHandler {
    public:
        FunctionEventHandler(std::shared_ptr<FunctionWrapper> wrapper, uint64_t id)
            : wrapper_(std::move(wrapper)), subscription_id_(id) {}

        void handle_event(const std::shared_ptr<IEvent>& event) override {
            if (!wrapper_) return;
            if (auto derived = std::dynamic_pointer_cast<EventType>(event)) {
                wrapper_->try_execute(derived->payload());
            }
        }

        bool try_handle_event(const std::shared_ptr<IEvent>& event) override {
            if (!wrapper_) return false;
            if (auto derived = std::dynamic_pointer_cast<EventType>(event)) {
                return wrapper_->try_execute(derived->payload());
            }
            return false;
        }

        std::type_index get_event_type() const override {
            return std::type_index(typeid(EventType));
        }

        std::weak_ptr<void> get_owner() const override { return std::weak_ptr<void>(); }
        void deactivate() override {}
        void mark_removed() override { wrapper_.reset(); }
        bool is_removed() const override { return !wrapper_; }
        uint64_t get_subscription_id() const override { return subscription_id_; }

    private:
        std::shared_ptr<FunctionWrapper> wrapper_;
        uint64_t subscription_id_;
    };

    HandlerEntry entry;
    entry.id = id;
    entry.handler = std::make_shared<FunctionEventHandler>(wrapper, id);
    entry.pending_execution = std::make_shared<std::atomic<bool>>(false);
    entry.removed = std::make_shared<std::atomic<bool>>(false);
    entry.counted = true;

    handlers_[std::type_index(typeid(EventType))].push_back(std::move(entry));
    total_handler_count_.fetch_add(1, std::memory_order_acq_rel);

    if (logger_) {
        try {
            logger_->log(ILogger::Level::Debug, "Lambda handler subscribed with ID: " + std::to_string(id));
        } catch (...) {}
    }

    return id;
}

template<typename EventType>
void EventDispatcher::unsubscribe_all() noexcept {
    if (destruction_flag_.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lock(handlers_mutex_);
    auto it = handlers_.find(std::type_index(typeid(EventType)));
    if (it == handlers_.end()) return;

    for (auto & entry : it->second) {
        if (entry.handler) {
            entry.handler->deactivate();
            entry.handler->mark_removed();
        }
        if (entry.removed) entry.removed->store(true, std::memory_order_release);
        if (entry.counted) {
            entry.counted = false;
            total_handler_count_.fetch_sub(1, std::memory_order_acq_rel);
        }
    }
}

template<typename EventType, typename... Args>
void EventDispatcher::dispatch(Args&&... args) noexcept {
    if (destruction_flag_.load(std::memory_order_acquire)) return;

    std::shared_ptr<IEvent> event;
    try {
        event = std::make_shared<EventType>(std::forward<Args>(args)...);
    } catch (...) {
        // construction failed; nothing to do
        return;
    }

    // snapshot handlers
    std::vector<std::shared_ptr<IEventHandler>> snapshot;
    {
        std::lock_guard<std::mutex> lock(handlers_mutex_);
        auto it = handlers_.find(std::type_index(typeid(EventType)));
        if (it != handlers_.end()) {
            for (const auto& e : it->second) {
                bool removed_flag = e.removed && e.removed->load(std::memory_order_acquire);
                if (!removed_flag && e.handler && !e.handler->is_removed()) {
                    snapshot.push_back(e.handler);
                }
            }
        }
    }

    for (auto & h : snapshot) {
        try {
            if (h && !h->is_removed()) h->try_handle_event(event);
        } catch (const std::exception& ex) {
            // notify user callback but don't throw from here
            try {
                invoke_exception_callback(h->get_subscription_id(), ex);
            } catch (...) {}
        } catch (...) {
            // unknown
        }
    }
}

template<typename EventType, typename... Args>
std::future<void> EventDispatcher::dispatch_async(Args&&... args) {
    // create shared promise which will be stored in queue
    auto promise_ptr = std::make_shared<std::promise<void>>();
    std::future<void> fut = promise_ptr->get_future();

    if (destruction_flag_.load(std::memory_order_acquire)) {
        try {
            promise_ptr->set_exception(std::make_exception_ptr(EventEngineException("Dispatcher is being destroyed")));
        } catch (...) {}
        return fut;
    }

    if (!can_process_events()) {
        try {
            promise_ptr->set_exception(std::make_exception_ptr(EventEngineException("Dispatcher not processing")));
        } catch (...) {}
        return fut;
    }

    std::shared_ptr<IEvent> event;
    try {
        event = std::make_shared<EventType>(std::forward<Args>(args)...);
    } catch (...) {
        try {
            promise_ptr->set_exception(std::make_exception_ptr(EventEngineException("Event construction failed")));
        } catch (...) {}
        return fut;
    }

    auto wrapper = std::make_shared<EventWrapper>(event, promise_ptr);

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (destruction_flag_.load(std::memory_order_acquire) || !can_process_events()) {
            try {
                if (!wrapper->promise_set->exchange(true)) {
                    wrapper->promise->set_exception(std::make_exception_ptr(EventEngineException("Dispatcher stopped")));
                }
            } catch (...) {}
            return fut;
        }

        if (event_queue_.size() >= max_queue_size_) {
            try {
                if (!wrapper->promise_set->exchange(true)) {
                    wrapper->promise->set_exception(std::make_exception_ptr(EventEngineException("Event queue full")));
                }
            } catch (...) {}
            return fut;
        }

        event_queue_.push_back(wrapper);
    }

    queue_condition_.notify_one();
    return fut;
}


} 

#endif 