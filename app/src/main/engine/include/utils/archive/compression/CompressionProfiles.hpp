// include/compression/CompressionProfiles.hpp
#ifndef COMPRESSIONPROFILES_HPP
#define COMPRESSIONPROFILES_HPP

#include "../common/Types.hpp"
#include <unordered_map>
#include <string>

namespace compression {
namespace compression {

class CompressionProfiles : public common::NonCopyable {
private:
    std::unordered_map<std::string, common::CompressionConfig> profiles_;
    
public:
    CompressionProfiles();
    
    void addProfile(const std::string& name, const common::CompressionConfig& config);
    void removeProfile(const std::string& name);
    bool hasProfile(const std::string& name) const;
    
    common::CompressionConfig getProfile(const std::string& name) const;
    common::CompressionConfig getProfile(const std::string& name, 
                                       const common::CompressionConfig& defaultConfig) const;
    
    common::CompressionConfig createProfile(common::CompressionAlgorithm algorithm,
                                          common::CompressionLevel level,
                                          common::ContentType contentType,
                                          size_t chunkSize = common::Constants::DEFAULT_CHUNK_SIZE);
    
    std::vector<std::string> getProfileNames() const;
    void clear();
    
    static CompressionProfiles& getInstance();
    
private:
    void initializeDefaultProfiles();
};

} // namespace compression
} // namespace compression

#endif