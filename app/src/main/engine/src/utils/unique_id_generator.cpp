#include "../include/tools/unique_id_generator.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <sys/time.h>

uint64_t UniqueIdGenerator::sequential_counter = 0;
uint64_t UniqueIdGenerator::hash_seed = 0x1234567890ABCDEF;
std::string UniqueIdGenerator::custom_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

std::string UniqueIdGenerator::generateUUID() {
    std::vector<uint8_t> bytes = generateRandomBytes(16);
    
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            ss << "-";
        }
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return ss.str();
}

std::string UniqueIdGenerator::generateTimestampId() {
    uint64_t timestamp = getHighResolutionTimestamp();
    uint64_t random_part = getRandomEngine()() & 0xFFFF;
    
    std::stringstream ss;
    ss << std::hex << timestamp << std::hex << random_part;
    
    return ss.str();
}

std::string UniqueIdGenerator::generateRandomNumeric(uint32_t length) {
    static const std::string numeric_alphabet = "0123456789";
    return generateRandomString(length, numeric_alphabet);
}

std::string UniqueIdGenerator::generateRandomAlphanumeric(uint32_t length) {
    return generateRandomString(length, custom_alphabet);
}

std::string UniqueIdGenerator::generateSequentialId(const std::string& namespace_str) {
    uint64_t timestamp = getCurrentTimestamp();
    uint64_t sequence = ++sequential_counter;
    
    std::stringstream ss;
    if (!namespace_str.empty()) {
        ss << namespace_str << "_";
    }
    ss << timestamp << "_" << sequence;
    
    return ss.str();
}

std::string UniqueIdGenerator::generateHashBasedId(const std::string& data) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.length());
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    
    std::vector<uint8_t> hash_bytes(hash, hash + SHA256_DIGEST_LENGTH);
    std::string hex_hash = bytesToHex(hash_bytes);
    
    return hex_hash.substr(0, 32);
}

std::string UniqueIdGenerator::generateSecureRandomId(uint32_t length) {
    std::vector<uint8_t> bytes = generateSecureRandomBytes(length);
    return bytesToHex(bytes);
}

std::string UniqueIdGenerator::generateCustomId(const GeneratorConfig& config) {
    std::stringstream ss;
    
    if (!config.prefix.empty()) {
        ss << config.prefix;
    }
    
    switch (config.type) {
        case IdType::UUID4:
            ss << generateUUID();
            break;
        case IdType::TimestampBased:
            ss << generateTimestampId();
            break;
        case IdType::RandomNumeric:
            ss << generateRandomNumeric(config.length);
            break;
        case IdType::RandomAlphanumeric:
            ss << generateRandomAlphanumeric(config.length);
            break;
        case IdType::Sequential:
            ss << generateSequentialId();
            break;
        case IdType::HashBased:
            ss << generateHashBasedId(config.prefix + std::to_string(getHighResolutionTimestamp()));
            break;
        case IdType::SecureRandom:
            ss << generateSecureRandomId(config.length);
            break;
    }
    
    if (config.include_timestamp) {
        ss << "_" << getHighResolutionTimestamp();
    }
    
    if (config.include_mac) {
        ss << "_" << getMachineIdentifier();
    }
    
    if (!config.suffix.empty()) {
        ss << config.suffix;
    }
    
    std::string id = ss.str();
    
    if (config.length > 0 && id.length() > config.length) {
        id = id.substr(0, config.length);
    }
    
    return id;
}

std::vector<std::string> UniqueIdGenerator::generateBatch(uint32_t count, const GeneratorConfig& config) {
    std::vector<std::string> ids;
    ids.reserve(count);
    
    for (uint32_t i = 0; i < count; i++) {
        ids.push_back(generateCustomId(config));
    }
    
    return ids;
}

bool UniqueIdGenerator::validateId(const std::string& id, const GeneratorConfig& config) {
    if (id.empty()) return false;
    
    if (!config.prefix.empty() && id.find(config.prefix) != 0) {
        return false;
    }
    
    if (!config.suffix.empty() && id.rfind(config.suffix) != id.length() - config.suffix.length()) {
        return false;
    }
    
    if (config.length > 0 && id.length() != config.length) {
        return false;
    }
    
    switch (config.type) {
        case IdType::UUID4:
            if (id.length() != 36) return false;
            break;
        case IdType::RandomNumeric:
            for (char c : id) {
                if (!std::isdigit(c)) return false;
            }
            break;
        case IdType::RandomAlphanumeric:
            for (char c : id) {
                if (!std::isalnum(c)) return false;
            }
            break;
        default:
            break;
    }
    
    return true;
}

std::string UniqueIdGenerator::normalizeId(const std::string& id) {
    std::string normalized = id;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::toupper);
    
    size_t pos;
    while ((pos = normalized.find('-')) != std::string::npos) {
        normalized.erase(pos, 1);
    }
    
    return normalized;
}

uint64_t UniqueIdGenerator::getTimestampFromId(const std::string& id) {
    try {
        size_t pos = id.find_last_of('_');
        if (pos != std::string::npos) {
            std::string timestamp_str = id.substr(pos + 1);
            return std::stoull(timestamp_str, nullptr, 16);
        }
    } catch (...) {
    }
    
    return 0;
}

std::string UniqueIdGenerator::extractNamespace(const std::string& id) {
    size_t pos = id.find('_');
    if (pos != std::string::npos) {
        return id.substr(0, pos);
    }
    return "";
}

void UniqueIdGenerator::setSequentialBase(uint64_t base) {
    sequential_counter = base;
}

void UniqueIdGenerator::setCustomAlphabet(const std::string& alphabet) {
    if (!alphabet.empty()) {
        custom_alphabet = alphabet;
    }
}

void UniqueIdGenerator::setHashSeed(uint64_t seed) {
    hash_seed = seed;
}

std::string UniqueIdGenerator::getMachineIdentifier() {
    static std::string machine_id;
    
    if (machine_id.empty()) {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            machine_id = std::to_string(hashString(hostname));
        } else {
            machine_id = "unknown";
        }
    }
    
    return machine_id;
}

uint64_t UniqueIdGenerator::getProcessIdentifier() {
    return static_cast<uint64_t>(getpid());
}

std::string UniqueIdGenerator::generateRandomString(uint32_t length, const std::string& alphabet) {
    if (alphabet.empty() || length == 0) return "";
    
    std::uniform_int_distribution<> dist(0, alphabet.size() - 1);
    std::string result;
    result.reserve(length);
    
    for (uint32_t i = 0; i < length; i++) {
        result += alphabet[dist(getRandomEngine())];
    }
    
    return result;
}

std::string UniqueIdGenerator::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

std::vector<uint8_t> UniqueIdGenerator::generateRandomBytes(uint32_t count) {
    std::vector<uint8_t> bytes(count);
    std::uniform_int_distribution<> dist(0, 255);
    
    for (uint32_t i = 0; i < count; i++) {
        bytes[i] = static_cast<uint8_t>(dist(getRandomEngine()));
    }
    
    return bytes;
}

std::vector<uint8_t> UniqueIdGenerator::generateSecureRandomBytes(uint32_t count) {
    std::vector<uint8_t> bytes(count);
    
    if (RAND_bytes(bytes.data(), count) == 1) {
        return bytes;
    }
    
    return generateRandomBytes(count);
}

uint64_t UniqueIdGenerator::hashString(const std::string& str) {
    uint64_t hash = hash_seed;
    
    for (char c : str) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

uint64_t UniqueIdGenerator::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

uint64_t UniqueIdGenerator::getHighResolutionTimestamp() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

std::mt19937& UniqueIdGenerator::getRandomEngine() {
    static std::mt19937 engine(getRandomDevice()());
    return engine;
}

std::random_device& UniqueIdGenerator::getRandomDevice() {
    static std::random_device device;
    return device;
}