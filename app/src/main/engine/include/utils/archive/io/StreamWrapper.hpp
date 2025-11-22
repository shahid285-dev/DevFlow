// include/io/StreamWrapper.hpp
#ifndef STREAMWRAPPER_HPP
#define STREAMWRAPPER_HPP

#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <system_error>
#include <memory>
#include <functional>

namespace compression {
namespace io {

class IStream {
public:
    virtual ~IStream() = default;
    
    virtual std::error_code read(common::ByteArray& buffer, size_t bytesToRead) = 0;
    virtual std::error_code write(const common::ByteArray& buffer) = 0;
    virtual std::error_code seek(size_t position) = 0;
    virtual size_t tell() const = 0;
    virtual bool endOfStream() const = 0;
    virtual size_t getSize() const = 0;
    virtual void close() = 0;
};

class StreamWrapper : public common::NonCopyable {
private:
    std::unique_ptr<IStream> stream_;
    std::string streamId_;
    
public:
    explicit StreamWrapper(std::unique_ptr<IStream> stream, const std::string& id = "");
    ~StreamWrapper();
    
    std::error_code read(common::ByteArray& buffer, size_t bytesToRead);
    std::error_code write(const common::ByteArray& buffer);
    std::error_code seek(size_t position);
    size_t tell() const;
    bool endOfStream() const;
    size_t getSize() const;
    void close();
    
    std::string getStreamId() const { return streamId_; }
    bool isValid() const { return stream_ != nullptr; }
    
    template<typename T>
    T* as() { return dynamic_cast<T*>(stream_.get()); }
};

class CallbackStream : public IStream {
private:
    using ReadCallback = std::function<std::error_code(common::ByteArray&, size_t)>;
    using WriteCallback = std::function<std::error_code(const common::ByteArray&)>;
    using SeekCallback = std::function<std::error_code(size_t)>;
    using TellCallback = std::function<size_t()>;
    using EOSCallback = std::function<bool()>;
    using SizeCallback = std::function<size_t()>;
    using CloseCallback = std::function<void()>;
    
    ReadCallback readCallback_;
    WriteCallback writeCallback_;
    SeekCallback seekCallback_;
    TellCallback tellCallback_;
    EOSCallback eosCallback_;
    SizeCallback sizeCallback_;
    CloseCallback closeCallback_;
    
public:
    CallbackStream(ReadCallback readCb, WriteCallback writeCb = nullptr);
    
    void setSeekCallback(SeekCallback cb) { seekCallback_ = cb; }
    void setTellCallback(TellCallback cb) { tellCallback_ = cb; }
    void setEOSCallback(EOSCallback cb) { eosCallback_ = cb; }
    void setSizeCallback(SizeCallback cb) { sizeCallback_ = cb; }
    void setCloseCallback(CloseCallback cb) { closeCallback_ = cb; }
    
    std::error_code read(common::ByteArray& buffer, size_t bytesToRead) override;
    std::error_code write(const common::ByteArray& buffer) override;
    std::error_code seek(size_t position) override;
    size_t tell() const override;
    bool endOfStream() const override;
    size_t getSize() const override;
    void close() override;
};

} // namespace io
} // namespace compression

#endif