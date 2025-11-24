#include "EventEngine.h"
#include <stdexcept>

namespace EventSystem {

EventDispatcher::EventDispatcher() 
    : processing_(false)
    , max_queue_size_(1000) {
    start_processing();
}

EventDispatcher::~EventDispatcher() {
    stop_processing();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void EventDispatcher::set_max_queue_size(size_t size) {
    max_queue_size_.store(size);
}

void EventDispatcher::start_processing() {
    bool expected = false;
    if (processing_.compare_exchange_strong(expected, true)) {
        worker_thread_ = std::thread(&EventDispatcher::process_events, this);
    }
}

void EventDispatcher::stop_processing() {
    bool expected = true;
    if (processing_.compare_exchange_strong(expected, false)) {
        queue_condition_.notify_all();
    }
}

void EventDispatcher::wait_until_empty() const {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    queue_condition_.wait(lock, [this]() {
        return event_queue_.empty();
    });
}

size_t EventDispatcher::get_pending_events() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return event_queue_.size();
}

void EventDispatcher::clear_pending_events() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    while (!event_queue_.empty()) {
        auto& wrapper = event_queue_.front();
        wrapper.promise.set_value();
        event_queue_.pop();
    }
}

void EventDispatcher::process_events() {
    while (processing_.load()) {
        EventWrapper wrapper;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_condition_.wait(lock, [this]() {
                return !event_queue_.empty() || !processing_.load();
            });

            if (!processing_.load() && event_queue_.empty()) {
                break;
            }

            if (event_queue_.empty()) {
                continue;
            }

            wrapper = std::move(event_queue_.front());
            event_queue_.pop();
        }

        if (wrapper.event) {
            std::vector<std::unique_ptr<IEventHandler>> handlers_copy;
            {
                std::lock_guard<std::mutex> lock(handlers_mutex_);
                auto it = handlers_.find(wrapper.event->get_type());
                if (it != handlers_.end()) {
                    for (const auto& handler : it->second) {
                        handlers_copy.push_back(std::make_unique<IEventHandler>(*handler));
                    }
                }
            }

            try {
                for (const auto& handler : handlers_copy) {
                    handler->handle_event(wrapper.event);
                }
                wrapper.promise.set_value();
            } catch (...) {
                wrapper.promise.set_exception(std::current_exception());
            }
        }
    }
}

ScopedSubscription::~ScopedSubscription() {
    if (dispatcher_ && handler_) {
        dispatcher_->unsubscribe(event_type_, handler_);
    }
}

ScopedSubscription::ScopedSubscription(ScopedSubscription&& other) noexcept
    : dispatcher_(other.dispatcher_)
    , event_type_(other.event_type_)
    , handler_(other.handler_) {
    other.dispatcher_ = nullptr;
    other.handler_ = nullptr;
}

ScopedSubscription& ScopedSubscription::operator=(ScopedSubscription&& other) noexcept {
    if (this != &other) {
        if (dispatcher_ && handler_) {
            dispatcher_->unsubscribe(event_type_, handler_);
        }
        
        dispatcher_ = other.dispatcher_;
        event_type_ = other.event_type_;
        handler_ = other.handler_;
        
        other.dispatcher_ = nullptr;
        other.handler_ = nullptr;
    }
    return *this;
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
        
        if (handler_list.empty()) {
            handlers_.erase(it);
        }
    }
}

void EventDispatcher::unsubscribe(const std::type_index& event_type, void* handler) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    auto it = handlers_.find(event_type);
    if (it != handlers_.end()) {
        auto& handler_list = it->second;
        handler_list.erase(
            std::remove_if(handler_list.begin(), handler_list.end(),
                [handler](const std::unique_ptr<IEventHandler>& event_handler) {
                    return event_handler.get() == handler;
                }),
            handler_list.end()
        );
        
        if (handler_list.empty()) {
            handlers_.erase(it);
        }
    }
}

}