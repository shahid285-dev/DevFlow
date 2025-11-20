#ifndef UNIQUE_ID_GENERATOR_H
#define UNIQUE_ID_GENERATOR_H

#include <string>
#include <cstdint>
#include <vector>
#include <random>

class UniqueIdGenerator {
public:
    enum class IdType {
        UUID4,
        TimestampBased,
        RandomNumeric,
        RandomAlphanumeric,
        Sequential,
        HashBased,
        SecureRandom
    };

    struct GeneratorConfig {
        IdType type;
        uint32_t length;
        bool include_timestamp;
        bool include_mac;
        std::string prefix;
        std::string suffix;
        std::string custom_alphabet;
    };

    static std::string generateUUID();
    static std::string generateTimestampId();
    static std::string generateRandomNumeric(uint32_t length);
    static std::string generateRandomAlphanumeric(uint32_t length);
    static std::string generateSequentialId(const std::string& namespace_str = "");
    static std::string generateHashBasedId(const std::string& data);
    static std::string generateSecureRandomId(uint32_t length);
    
    static std::string generateCustomId(const GeneratorConfig& config);
    static std::vector<std::string> generateBatch(uint32_t count, const GeneratorConfig& config);
    
    static bool validateId(const std::string& id, const GeneratorConfig& config);
    static std::string normalizeId(const std::string& id);
    
    static uint64_t getTimestampFromId(const std::string& id);
    static std::string extractNamespace(const std::string& id);
    
    static void setSequentialBase(uint64_t base);
    static void setCustomAlphabet(const std::string& alphabet);
    static void setHashSeed(uint64_t seed);
    
    static std::string getMachineIdentifier();
    static uint64_t getProcessIdentifier();

private:
    static std::string generateRandomString(uint32_t length, const std::string& alphabet);
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> generateRandomBytes(uint32_t count);
    static std::vector<uint8_t> generateSecureRandomBytes(uint32_t count);
    static uint64_t hashString(const std::string& str);
    static uint64_t getCurrentTimestamp();
    static uint64_t getHighResolutionTimestamp();
    
    static std::mt19937& getRandomEngine();
    static std::random_device& getRandomDevice();
    
    static uint64_t sequential_counter;
    static uint64_t hash_seed;
    static std::string custom_alphabet;
};

#endif