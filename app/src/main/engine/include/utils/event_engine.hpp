#ifndef EVENT_ENGINE_H
#define EVENT_ENGINE_H

#include <memory>
#include <unordered_map>
#include <vector>
#include <functional>
#include <typeindex>
#include <mutex>
#include <atomic>
#include <queue>
#include <future>
#include <thread>
#include <condition_variable>

namespace EventSystem {

class IEvent {
public:
    virtual ~IEvent() = default;
    virtual std::type_index get_type() const = 0;
};

template<typename EventType>
class Event : public IEvent {
public:
    std::type_index get_type() const override {
        return std::type_index(typeid(EventType));
    }
};

class IEventHandler {
public:
    virtual ~IEventHandler() = default;
    virtual void handle_event(const std::shared_ptr<IEvent>& event) = 0;
    virtual std::type_index get_event_type() const = 0;
};

template<typename EventType, typename HandlerClass>
class EventHandler : public IEventHandler {
public:
    using HandlerFunction = void (HandlerClass::*)(const EventType&);

    EventHandler(HandlerClass* instance, HandlerFunction function) 
        : instance_(instance), function_(function) {}

    void handle_event(const std::shared_ptr<IEvent>& event) override {
        if (auto derived_event = std::dynamic_pointer_cast<EventType>(event)) {
            (instance_->*function_)(*derived_event);
        }
    }

    std::type_index get_event_type() const override {
        return std::type_index(typeid(EventType));
    }

private:
    HandlerClass* instance_;
    HandlerFunction function_;
};

class EventDispatcher {
public:
    EventDispatcher();
    ~EventDispatcher();

    template<typename EventType, typename HandlerClass>
    void subscribe(HandlerClass* handler, typename EventHandler<EventType, HandlerClass>::HandlerFunction function);

    template<typename EventType, typename Function>
    void subscribe(Function&& function);

    template<typename EventType>
    void unsubscribe();

    template<typename EventType, typename HandlerClass>
    void unsubscribe(HandlerClass* handler);

    template<typename EventType, typename... Args>
    void dispatch(Args&&... args);

    template<typename EventType, typename... Args>
    std::future<void> dispatch_async(Args&&... args);

    void set_max_queue_size(size_t size);
    void start_processing();
    void stop_processing();
    void wait_until_empty() const;
    size_t get_pending_events() const;
    void clear_pending_events();

private:
    void process_events();

    struct EventWrapper {
        std::shared_ptr<IEvent> event;
        std::promise<void> promise;
    };

    std::unordered_map<std::type_index, std::vector<std::unique_ptr<IEventHandler>>> handlers_;
    mutable std::mutex handlers_mutex_;

    std::queue<EventWrapper> event_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_condition_;

    std::atomic<bool> processing_;
    std::atomic<size_t> max_queue_size_;
    std::thread worker_thread_;
};

class ScopedSubscription {
public:
    ScopedSubscription() = default;
    
    template<typename EventType, typename HandlerClass>
    ScopedSubscription(EventDispatcher& dispatcher, 
                      HandlerClass* handler, 
                      typename EventHandler<EventType, HandlerClass>::HandlerFunction function);
    
    ~ScopedSubscription();
    
    ScopedSubscription(const ScopedSubscription&) = delete;
    ScopedSubscription& operator=(const ScopedSubscription&) = delete;
    
    ScopedSubscription(ScopedSubscription&& other) noexcept;
    ScopedSubscription& operator=(ScopedSubscription&& other) noexcept;

private:
    EventDispatcher* dispatcher_{nullptr};
    std::type_index event_type_{typeid(void)};
    void* handler_{nullptr};
};

template<typename EventType>
class EventChannel {
public:
    explicit EventChannel(EventDispatcher& dispatcher) : dispatcher_(dispatcher) {}

    template<typename... Args>
    void publish(Args&&... args) {
        dispatcher_.dispatch<EventType>(std::forward<Args>(args)...);
    }

    template<typename... Args>
    std::future<void> publish_async(Args&&... args) {
        return dispatcher_.dispatch_async<EventType>(std::forward<Args>(args)...);
    }

    template<typename HandlerClass>
    ScopedSubscription subscribe(HandlerClass* handler, 
                                typename EventHandler<EventType, HandlerClass>::HandlerFunction function) {
        return ScopedSubscription(dispatcher_, handler, function);
    }

    template<typename Function>
    ScopedSubscription subscribe(Function&& function) {
        dispatcher_.subscribe<EventType>(std::forward<Function>(function));
        return ScopedSubscription();
    }

private:
    EventDispatcher& dispatcher_;
};

template<typename EventType, typename HandlerClass>
void EventDispatcher::subscribe(HandlerClass* handler, 
                               typename EventHandler<EventType, HandlerClass>::HandlerFunction function) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    auto handler_ptr = std::make_unique<EventHandler<EventType, HandlerClass>>(handler, function);
    handlers_[std::type_index(typeid(EventType))].push_back(std::move(handler_ptr));
}

template<typename EventType, typename Function>
void EventDispatcher::subscribe(Function&& function) {
    struct FunctionWrapper {
        Function function;
        void operator()(const EventType& event) { function(event); }
    };

    static FunctionWrapper wrapper{std::forward<Function>(function)};
    
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    auto handler_ptr = std::make_unique<EventHandler<EventType, FunctionWrapper>>(&wrapper, &FunctionWrapper::operator());
    handlers_[std::type_index(typeid(EventType))].push_back(std::move(handler_ptr));
}

template<typename EventType>
void EventDispatcher::unsubscribe() {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    handlers_.erase(std::type_index(typeid(EventType)));
}

template<typename EventType, typename HandlerClass>
void EventDispatcher::unsubscribe(HandlerClass* handler) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    auto it = handlers_.find(std::type_index(typeid(EventType)));
    if (it != handlers_.end()) {
        auto& handler_list = it->second;
        handler_list.erase(
            std::remove_if(handler_list.begin(), handler_list.end(),
                [handler](const std::unique_ptr<IEventHandler>& event_handler) {
                    auto derived_handler = dynamic_cast<EventHandler<EventType, HandlerClass>*>(event_handler.get());
                    return derived_handler && derived_handler->instance_ == handler;
                }),
            handler_list.end()
        );
    }
}

template<typename EventType, typename... Args>
void EventDispatcher::dispatch(Args&&... args) {
    auto event = std::make_shared<EventType>(std::forward<Args>(args)...);
    
    std::vector<std::unique_ptr<IEventHandler>> handlers_copy;
    {
        std::lock_guard<std::mutex> lock(handlers_mutex_);
        auto it = handlers_.find(std::type_index(typeid(EventType)));
        if (it != handlers_.end()) {
            for (const auto& handler : it->second) {
                handlers_copy.push_back(std::unique_ptr<IEventHandler>(handler->clone()));
            }
        }
    }
    
    for (const auto& handler : handlers_copy) {
        handler->handle_event(event);
    }
}

template<typename EventType, typename... Args>
std::future<void> EventDispatcher::dispatch_async(Args&&... args) {
    auto event = std::make_shared<EventType>(std::forward<Args>(args)...);
    EventWrapper wrapper{event, std::promise<void>{}};
    auto future = wrapper.promise.get_future();
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (event_queue_.size() >= max_queue_size_.load()) {
            throw std::runtime_error("Event queue size limit exceeded");
        }
        event_queue_.push(std::move(wrapper));
    }
    
    queue_condition_.notify_one();
    return future;
}

template<typename EventType, typename HandlerClass>
ScopedSubscription::ScopedSubscription(EventDispatcher& dispatcher, 
                                      HandlerClass* handler, 
                                      typename EventHandler<EventType, HandlerClass>::HandlerFunction function)
    : dispatcher_(&dispatcher)
    , event_type_(typeid(EventType))
    , handler_(handler) {
    dispatcher.subscribe<EventType>(handler, function);
}

} 

#endif