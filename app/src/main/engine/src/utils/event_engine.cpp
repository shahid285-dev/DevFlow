/*
================== POTENTIAL IDENTIFIED ISSUES  [ Tue 25 Nov 1:58 AM  ] =======================

1.decrement_handler_count_safe() can undercount
If multiple handlers are removed in one cleanup cycle but only one decrement occurs, the global count may become inaccurate.
Risk
Statistics may become wrong → not security-critical, but correctness issue.
Fix
Decrement for each removed handler, not once per cleanup cycle.


2. cleanup_counter_ uses relaxed ordering
You use memory_order_relaxed for a variable that triggers structural modification of handlers_.
While technically safe due to outer mutex, the relaxed ordering might allow unnecessary cleanup delays.
Risk
Non-deterministic cleanup timing under heavy concurrency.
Fix
Use memory_order_acq_rel for predictable cleanup frequency.


3. Optional race: handler flags (pending_execution) stored as shared_ptr<atomic>
Two threads could write to the same atomic flag during handler removal + event dispatch, even though this is mostly controlled by mutex.
Risk
Very low; atomic covers correctness.
Main impact: redundant CAS failures, not corruption.
Fix
No need unless you want to refine correctness:
Use a separate "alive" flag guarded by handler mutex.


4. Heavy reliance on catch(...) blocks
Hidden error states can occur silently when logs fail or user callbacks throw.
Risk
Masked failures reduce observability and complicate debugging.
Fix
Provide a fallback error sink or a metrics counter for swallowed exceptions.

5. Possible starvation when queue is nearly full
When queue size approaches maximum, producers back off but consumers may drain slowly.
Your control logic is correct, but starvation is possible under extreme load.
Risk
Low; mostly performance-related.
Fix
Optional: introduce back-pressure strategy (e.g., exponential retry or producer timeout).


6. try_handle_event() return value ignored
Even if a handler explicitly signals "I did not handle this", the dispatcher discards the information.
Risk
Logic bug if handlers are expected to conditionally stop propagation.

Fix
Either remove return value or support "consume/continue" logic.
    
*/

#include "EventEngine.h"
#include <stdexcept>
#include <chrono>
#include <iostream>
#include <sstream>

namespace EventSystem {

EventDispatcher::EventDispatcher(std::shared_ptr<ILogger> logger)
    : logger_(logger ? logger : std::make_shared<NullLogger>()),
      processing_(false),
      destruction_flag_(false),
      drain_mode_(false),
      max_queue_size_(DEFAULT_MAX_QUEUE_SIZE),
      next_handler_id_(1),
      cleanup_counter_(0) {
    try {
        start_processing();
    } catch (...) {
        destruction_flag_.store(true, std::memory_order_release);
        throw;
    }
}

EventDispatcher::~EventDispatcher() noexcept {
    try {
        destruction_flag_.store(true, std::memory_order_release);
        stop_processing();
        clear_pending_events();
        {
            std::lock_guard<std::mutex> lk(handlers_mutex_);
            handlers_.clear();
        }
    } catch (...) {
        try {
            log_message(ILogger::Level::Critical, "Exception in destructor");
        } catch (...) {}
    }
}

bool EventDispatcher::can_process_events() const noexcept {
    return processing_.load(std::memory_order_acquire) &&
           !destruction_flag_.load(std::memory_order_acquire);
}

HandlerId EventDispatcher::generate_handler_id_unsafe() {
    HandlerId id = next_handler_id_.fetch_add(1, std::memory_order_acq_rel);
    if (id >= std::numeric_limits<HandlerId>::max() - ID_RESERVE) {
        throw HandlerIdExhaustedException();
    }
    return id;
}

void EventDispatcher::log_message(ILogger::Level level, const std::string& message) noexcept {
    if (!logger_) return;
    try {
        logger_->log(level, message);
    } catch (...) {}
}

void EventDispatcher::invoke_exception_callback(HandlerId handler_id, const std::exception& e) noexcept {
    std::lock_guard<std::mutex> lk(callback_mutex_);
    if (!exception_callback_) return;
    try {
        exception_callback_(handler_id, e);
    } catch (...) {
        try {
            log_message(ILogger::Level::Error, "Exception callback threw");
        } catch (...) {}
    }
}

void EventDispatcher::safe_promise_set(std::promise<void>& promise) noexcept {
    try {
        promise.set_value();
    } catch (...) {}
}

void EventDispatcher::safe_promise_set_exception(std::promise<void>& promise, const std::exception_ptr& exc) noexcept {
    try {
        promise.set_exception(exc);
    } catch (...) {}
}

void EventDispatcher::safe_execution_flag_reset(const std::vector<std::shared_ptr<std::atomic<bool>>>& execution_flags) noexcept {
    for (auto & f : execution_flags) {
        if (f) {
            try {
                f->store(false, std::memory_order_release);
            } catch (...) {}
        }
    }
}

void EventDispatcher::decrement_handler_count_safe() noexcept {
    size_t prev = total_handler_count_.load(std::memory_order_acquire);
    while (prev > 0) {
        if (total_handler_count_.compare_exchange_strong(prev, prev - 1, std::memory_order_acq_rel)) return;
    }
}

void EventDispatcher::drain_queue_on_stop() noexcept {
    std::deque<std::shared_ptr<EventWrapper>> pending;
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        pending = std::move(event_queue_);
        event_queue_.clear();
    }
    for (auto & w : pending) {
        if (!w) continue;
        try {
            if (w->promise_set && !w->promise_set->exchange(true)) {
                try {
                    w->promise->set_exception(std::make_exception_ptr(EventEngineException("Dispatcher stopped")));
                } catch (...) {}
            }
        } catch (...) {}
    }
}

void EventDispatcher::set_max_queue_size(size_t size) {
    if (size == 0 || size > ABSOLUTE_MAX_QUEUE) throw InvalidArgumentException("Invalid queue size");
    std::lock_guard<std::mutex> lk(queue_mutex_);
    max_queue_size_ = size;
}

void EventDispatcher::set_max_handlers(size_t max_handlers) {
    if (max_handlers == 0 || max_handlers > ABSOLUTE_MAX_HANDLERS) throw InvalidArgumentException("Invalid max handlers");
    std::lock_guard<std::mutex> lk(handlers_mutex_);
    max_handlers_ = max_handlers;
}

void EventDispatcher::set_handler_timeout(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lk(handlers_mutex_);
    handler_timeout_ = timeout;
}

void EventDispatcher::set_logger(std::shared_ptr<ILogger> logger) {
    if (!logger) throw InvalidArgumentException("logger cannot be null");
    logger_ = logger;
}

void EventDispatcher::set_exception_callback(ExceptionCallback callback) {
    std::lock_guard<std::mutex> lk(callback_mutex_);
    exception_callback_ = std::move(callback);
}

void EventDispatcher::start_processing() noexcept {
    std::lock_guard<std::mutex> lk(control_mutex_);
    bool expected = false;
    if (!processing_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
    drain_mode_.store(false, std::memory_order_release);
    try {
        worker_thread_ = std::thread(&EventDispatcher::process_events, this);
    } catch (...) {
        processing_.store(false, std::memory_order_release);
    }
}

void EventDispatcher::stop_processing() noexcept {
    {
        std::lock_guard<std::mutex> lk(control_mutex_);
        bool expected = true;
        if (!processing_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        } else {
            drain_mode_.store(true, std::memory_order_release);
        }
    }
    queue_condition_.notify_one();
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        stop_condition_.notify_all();
    }
    if (worker_thread_.joinable()) {
        try {
            worker_thread_.join();
        } catch (...) {}
    }
    drain_queue_on_stop();
}

bool EventDispatcher::wait_until_empty(std::chrono::milliseconds timeout) const {
    std::unique_lock<std::mutex> lk(queue_mutex_);
    if (timeout == std::chrono::milliseconds(0)) {
        while (!event_queue_.empty() && can_process_events()) {
            stop_condition_.wait(lk, [this]() { return event_queue_.empty() || !can_process_events(); });
        }
        return event_queue_.empty();
    }
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!event_queue_.empty() && can_process_events()) {
        auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::milliseconds::zero()) return false;
        if (!stop_condition_.wait_for(lk, std::chrono::duration_cast<std::chrono::milliseconds>(remaining),
                                     [this]() { return event_queue_.empty() || !can_process_events(); })) {
            return false;
        }
    }
    return event_queue_.empty();
}

size_t EventDispatcher::get_pending_events() const noexcept {
    std::lock_guard<std::mutex> lk(queue_mutex_);
    return event_queue_.size();
}

size_t EventDispatcher::get_handler_count() const noexcept {
    return total_handler_count_.load(std::memory_order_acquire);
}

void EventDispatcher::clear_pending_events() noexcept {
    std::deque<std::shared_ptr<EventWrapper>> pending;
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        pending = std::move(event_queue_);
        event_queue_.clear();
    }
    for (auto & w : pending) {
        if (!w) continue;
        try {
            if (w->promise_set && !w->promise_set->exchange(true)) {
                try {
                    w->promise->set_exception(std::make_exception_ptr(EventEngineException("Pending events cleared")));
                } catch (...) {}
            }
        } catch (...) {}
    }
}

void EventDispatcher::force_cleanup() noexcept {
    cleanup_inactive_handlers();
}

void EventDispatcher::cleanup_inactive_handlers() noexcept {
    std::lock_guard<std::mutex> lk(handlers_mutex_);
    size_t removed_count = 0;
    for (auto it = handlers_.begin(); it != handlers_.end();) {
        auto & vec = it->second;
        vec.erase(std::remove_if(vec.begin(), vec.end(),
            [this, &removed_count](HandlerEntry & entry) -> bool {
                bool owner_alive = entry.handler && !entry.handler->get_owner().expired();
                bool pending = entry.pending_execution && entry.pending_execution->load(std::memory_order_acquire);
                bool handler_removed = (entry.removed && entry.removed->load(std::memory_order_acquire)) ||
                                       (entry.handler && entry.handler->is_removed());
                bool can_remove = !pending && (!owner_alive || handler_removed);
                if (can_remove && entry.counted) {
                    entry.counted = false;
                    removed_count++;
                }
                return can_remove;
            }), vec.end());
        if (vec.empty()) {
            it = handlers_.erase(it);
        } else {
            ++it;
        }
    }
    if (removed_count > 0) {
        decrement_handler_count_safe();
    }
    cleanup_counter_.store(0, std::memory_order_release);
}

void EventDispatcher::process_events() noexcept {
    while (can_process_events() || (drain_mode_.load(std::memory_order_acquire) && !event_queue_.empty())) {
        std::shared_ptr<EventWrapper> wrapper;
        {
            std::unique_lock<std::mutex> lk(queue_mutex_);
            if (!drain_mode_.load(std::memory_order_acquire)) {
                queue_condition_.wait(lk, [this]() { return !event_queue_.empty() || !can_process_events(); });
            } else {
                if (event_queue_.empty()) break;
            }
            if (!can_process_events() && event_queue_.empty()) break;
            if (!event_queue_.empty()) {
                wrapper = std::move(event_queue_.front());
                event_queue_.pop_front();
                stop_condition_.notify_all();
            } else {
                continue;
            }
        }
        if (!wrapper || !wrapper->event) {
            continue;
        }
        std::vector<std::shared_ptr<IEventHandler>> handlers_copy;
        std::vector<std::shared_ptr<std::atomic<bool>>> exec_flags;
        {
            std::lock_guard<std::mutex> lk(handlers_mutex_);
            auto it = handlers_.find(wrapper->event->get_type());
            if (it != handlers_.end()) {
                for (auto & entry : it->second) {
                    bool entry_removed = entry.removed && entry.removed->load(std::memory_order_acquire);
                    bool is_pending = entry.pending_execution && entry.pending_execution->load(std::memory_order_relaxed);
                    if (!is_pending && !entry_removed && entry.handler) {
                        bool expected = false;
                        if (entry.pending_execution && entry.pending_execution->compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                            handlers_copy.push_back(entry.handler);
                            exec_flags.push_back(entry.pending_execution);
                        }
                    }
                }
            }
        }
        std::exception_ptr caught = nullptr;
        for (auto & h : handlers_copy) {
            if (!h || h->is_removed()) {
                continue;
            }
            try {
                if (h->try_handle_event(wrapper->event)) {
                }
            } catch (const std::exception & ex) {
                try {
                    invoke_exception_callback(h->get_subscription_id(), ex);
                } catch (...) {}
                if (!caught) caught = std::current_exception();
            } catch (...) {
                if (!caught) caught = std::current_exception();
            }
        }
        safe_execution_flag_reset(exec_flags);
        if (wrapper->promise_set) {
            try {
                if (!wrapper->promise_set->exchange(true)) {
                    try {
                        if (caught) {
                            wrapper->promise->set_exception(caught);
                        } else {
                            wrapper->promise->set_value();
                        }
                    } catch (...) {}
                }
            } catch (...) {}
        }
        if (cleanup_counter_.fetch_add(1, std::memory_order_relaxed) >= CLEANUP_THRESHOLD) {
            cleanup_inactive_handlers();
        }
    }
    cleanup_inactive_handlers();
}

ScopedSubscription::ScopedSubscription(EventDispatcher* dispatcher, HandlerId id)
    : dispatcher_(dispatcher), id_(id) {
    if (!dispatcher_ || id_ == 0) throw InvalidArgumentException("Invalid dispatcher or handler ID");
}

ScopedSubscription::~ScopedSubscription() noexcept {
    try {
        if (dispatcher_ && id_ != 0) dispatcher_->unsubscribe(id_);
    } catch (...) {}
}

ScopedSubscription::ScopedSubscription(ScopedSubscription&& other) noexcept
    : dispatcher_(other.dispatcher_), id_(other.id_) {
    other.dispatcher_ = nullptr;
    other.id_ = 0;
}

ScopedSubscription& ScopedSubscription::operator=(ScopedSubscription&& other) noexcept {
    if (this != &other) {
        try {
            if (dispatcher_ && id_ != 0) dispatcher_->unsubscribe(id_);
        } catch (...) {}
        dispatcher_ = other.dispatcher_;
        id_ = other.id_;
        other.dispatcher_ = nullptr;
        other.id_ = 0;
    }
    return *this;
}

bool ScopedSubscription::unsubscribe() noexcept {
    if (!dispatcher_ || id_ == 0) return false;
    try {
        bool res = dispatcher_->unsubscribe(id_);
        dispatcher_ = nullptr;
        id_ = 0;
        return res;
    } catch (...) {
        return false;
    }
}

} 