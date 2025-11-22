// src/io/StreamWrapper.cpp
#include "../../include/io/StreamWrapper.hpp"

compression::io::StreamWrapper::StreamWrapper(std::unique_ptr<compression::io::IStream> stream, const std::string& id)
    : stream_(std::move(stream)), streamId_(id) {}

compression::io::StreamWrapper::~StreamWrapper() {
    close();
}

std::error_code compression::io::StreamWrapper::read(compression::common::ByteArray& buffer, size_t bytesToRead) {
    if (!stream_) {
        return compression::common::ErrorCode::STREAM_ERROR;
    }
    return stream_->read(buffer, bytesToRead);
}

std::error_code compression::io::StreamWrapper::write(const compression::common::ByteArray& buffer) {
    if (!stream_) {
        return compression::common::ErrorCode::STREAM_ERROR;
    }
    return stream_->write(buffer);
}

std::error_code compression::io::StreamWrapper::seek(size_t position) {
    if (!stream_) {
        return compression::common::ErrorCode::STREAM_ERROR;
    }
    return stream_->seek(position);
}

size_t compression::io::StreamWrapper::tell() const {
    if (!stream_) {
        return 0;
    }
    return stream_->tell();
}

bool compression::io::StreamWrapper::endOfStream() const {
    if (!stream_) {
        return true;
    }
    return stream_->endOfStream();
}

size_t compression::io::StreamWrapper::getSize() const {
    if (!stream_) {
        return 0;
    }
    return stream_->getSize();
}

void compression::io::StreamWrapper::close() {
    if (stream_) {
        stream_->close();
    }
}

compression::io::CallbackStream::CallbackStream(compression::io::CallbackStream::ReadCallback readCb, 
                                               compression::io::CallbackStream::WriteCallback writeCb)
    : readCallback_(readCb), writeCallback_(writeCb) {}

std::error_code compression::io::CallbackStream::read(compression::common::ByteArray& buffer, size_t bytesToRead) {
    if (!readCallback_) {
        return compression::common::ErrorCode::STREAM_ERROR;
    }
    return readCallback_(buffer, bytesToRead);
}

std::error_code compression::io::CallbackStream::write(const compression::common::ByteArray& buffer) {
    if (!writeCallback_) {
        return compression::common::ErrorCode::STREAM_ERROR;
    }
    return writeCallback_(buffer);
}

std::error_code compression::io::CallbackStream::seek(size_t position) {
    if (!seekCallback_) {
        return compression::common::ErrorCode::UNSUPPORTED_FEATURE;
    }
    return seekCallback_(position);
}

size_t compression::io::CallbackStream::tell() const {
    if (!tellCallback_) {
        return 0;
    }
    return tellCallback_();
}

bool compression::io::CallbackStream::endOfStream() const {
    if (!eosCallback_) {
        return false;
    }
    return eosCallback_();
}

size_t compression::io::CallbackStream::getSize() const {
    if (!sizeCallback_) {
        return 0;
    }
    return sizeCallback_();
}

void compression::io::CallbackStream::close() {
    if (closeCallback_) {
        closeCallback_();
    }
}