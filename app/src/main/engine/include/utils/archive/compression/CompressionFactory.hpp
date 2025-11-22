// include/compression/CompressionFactory.hpp
#ifndef COMPRESSIONFACTORY_HPP
#define COMPRESSIONFACTORY_HPP

#include "ICompressionStrategy.hpp"
#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <memory>
#include <unordered_map>
#include <functional>

namespace compression {
namespace compression {

class CompressionFactory : public common::NonCopyable {
private:
    using CreatorFunc = std::function<std::unique_ptr<ICompressionStrategy>()>;
    std::unordered_map<common::CompressionAlgorithm, CreatorFunc> creators_;
    std::unordered_map<std::string, common::CompressionAlgorithm> nameToAlgorithm_;
    
public:
    CompressionFactory();
    
    void registerAlgorithm(common::CompressionAlgorithm algorithm, 
                          CreatorFunc creator,
                          const std::string& name);
    
    void unregisterAlgorithm(common::CompressionAlgorithm algorithm);
    
    std::unique_ptr<ICompressionStrategy> create(common::CompressionAlgorithm algorithm);
    std::unique_ptr<ICompressionStrategy> create(const std::string& algorithmName);
    
    common::CompressionAlgorithm detectAlgorithm(const common::ByteArray& data) const;
    common::CompressionAlgorithm detectAlgorithm(const common::Byte* data, size_t size) const;
    
    std::vector<common::CompressionAlgorithm> getSupportedAlgorithms() const;
    std::vector<std::string> getSupportedAlgorithmNames() const;
    
    bool isAlgorithmSupported(common::CompressionAlgorithm algorithm) const;
    bool isAlgorithmSupported(const std::string& algorithmName) const;
    
    static CompressionFactory& getInstance();
    
private:
    void initializeDefaultAlgorithms();
};

} // namespace compression
} // namespace compression

#endif