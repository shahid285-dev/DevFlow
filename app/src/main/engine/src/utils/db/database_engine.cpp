#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sqlite3.h>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>

#include "metrics_base.hpp"



class DatabaseResult {
public:
    bool success;
    std::string message;
    std::vector<std::unordered_map<std::string, std::string>> data;
    int affectedRows;
    int lastInsertId;
    std::string query;
    
    DatabaseResult() : success(false), affectedRows(0), lastInsertId(-1) {}
};

class DatabaseColumn {
public:
    std::string name;
    std::string type;
    bool primaryKey;
    bool autoIncrement;
    bool notNull;
    std::string defaultValue;
    bool indexed;

    DatabaseColumn(const std::string& colName, const std::string& colType) 
        : name(colName), type(colType), primaryKey(false), autoIncrement(false), 
          notNull(false), indexed(false) {}
};

class DatabaseTable {
public:
    std::string name;
    std::vector<DatabaseColumn> columns;
    std::string conflictResolution;
};

class QueryBuilder {
private:
    std::string tableName;
    std::vector<std::string> selectColumns;
    std::vector<std::string> whereConditions;
    std::vector<std::string> orderByColumns;
    std::vector<std::string> groupByColumns;
    std::string havingCondition;
    int limitValue;
    int offsetValue;
    std::vector<std::pair<std::string, std::string>> setValues;
    std::vector<std::string> insertColumns;
    std::vector<std::vector<std::string>> insertValues;
    std::string queryType;
    std::string conflictResolution;

public:
    QueryBuilder() : limitValue(-1), offsetValue(-1) {}

    QueryBuilder& select(const std::vector<std::string>& columns = {"*"}) {
        queryType = "SELECT";
        selectColumns = columns;
        return *this;
    }

    QueryBuilder& from(const std::string& table) {
        tableName = table;
        return *this;
    }

    QueryBuilder& where(const std::string& condition) {
        whereConditions.push_back(condition);
        return *this;
    }

    QueryBuilder& orderBy(const std::string& column, bool ascending = true) {
        orderByColumns.push_back(column + (ascending ? " ASC" : " DESC"));
        return *this;
    }

    QueryBuilder& groupBy(const std::vector<std::string>& columns) {
        groupByColumns = columns;
        return *this;
    }

    QueryBuilder& having(const std::string& condition) {
        havingCondition = condition;
        return *this;
    }

    QueryBuilder& limit(int limit) {
        limitValue = limit;
        return *this;
    }

    QueryBuilder& offset(int offset) {
        offsetValue = offset;
        return *this;
    }

    QueryBuilder& update(const std::string& table) {
        queryType = "UPDATE";
        tableName = table;
        return *this;
    }

    QueryBuilder& set(const std::string& column, const std::string& value) {
        setValues.push_back({column, value});
        return *this;
    }

    QueryBuilder& insertInto(const std::string& table, const std::vector<std::string>& columns) {
        queryType = "INSERT";
        tableName = table;
        insertColumns = columns;
        return *this;
    }

    QueryBuilder& values(const std::vector<std::string>& values) {
        insertValues.push_back(values);
        return *this;
    }

    QueryBuilder& onConflict(const std::string& resolution) {
        conflictResolution = resolution;
        return *this;
    }

    QueryBuilder& deleteFrom(const std::string& table) {
        queryType = "DELETE";
        tableName = table;
        return *this;
    }

    std::string build() {
        std::stringstream query;

        if (queryType == "SELECT") {
            query << "SELECT ";
            for (size_t i = 0; i < selectColumns.size(); i++) {
                if (i > 0) query << ", ";
                query << selectColumns[i];
            }
            query << " FROM " << tableName;

            if (!whereConditions.empty()) {
                query << " WHERE ";
                for (size_t i = 0; i < whereConditions.size(); i++) {
                    if (i > 0) query << " AND ";
                    query << whereConditions[i];
                }
            }

            if (!groupByColumns.empty()) {
                query << " GROUP BY ";
                for (size_t i = 0; i < groupByColumns.size(); i++) {
                    if (i > 0) query << ", ";
                    query << groupByColumns[i];
                }
            }

            if (!havingCondition.empty()) {
                query << " HAVING " << havingCondition;
            }

            if (!orderByColumns.empty()) {
                query << " ORDER BY ";
                for (size_t i = 0; i < orderByColumns.size(); i++) {
                    if (i > 0) query << ", ";
                    query << orderByColumns[i];
                }
            }

            if (limitValue > 0) {
                query << " LIMIT " << limitValue;
                if (offsetValue > 0) {
                    query << " OFFSET " << offsetValue;
                }
            }
        }
        else if (queryType == "UPDATE") {
            query << "UPDATE " << tableName << " SET ";
            for (size_t i = 0; i < setValues.size(); i++) {
                if (i > 0) query << ", ";
                query << setValues[i].first << " = " << setValues[i].second;
            }

            if (!whereConditions.empty()) {
                query << " WHERE ";
                for (size_t i = 0; i < whereConditions.size(); i++) {
                    if (i > 0) query << " AND ";
                    query << whereConditions[i];
                }
            }
        }
        else if (queryType == "INSERT") {
            query << "INSERT";
            
            if (!conflictResolution.empty()) {
                query << " OR " << conflictResolution;
            }
            
            query << " INTO " << tableName;
            
            if (!insertColumns.empty()) {
                query << " (";
                for (size_t i = 0; i < insertColumns.size(); i++) {
                    if (i > 0) query << ", ";
                    query << insertColumns[i];
                }
                query << ")";
            }

            query << " VALUES ";
            for (size_t i = 0; i < insertValues.size(); i++) {
                if (i > 0) query << ", ";
                query << "(";
                for (size_t j = 0; j < insertValues[i].size(); j++) {
                    if (j > 0) query << ", ";
                    query << insertValues[i][j];
                }
                query << ")";
            }
        }
        else if (queryType == "DELETE") {
            query << "DELETE FROM " << tableName;

            if (!whereConditions.empty()) {
                query << " WHERE ";
                for (size_t i = 0; i < whereConditions.size(); i++) {
                    if (i > 0) query << " AND ";
                    query << whereConditions[i];
                }
            }
        }

        return query.str();
    }
};

class DatabaseTransaction {
private:
    sqlite3* db;
    bool active;

public:
    DatabaseTransaction(sqlite3* database) : db(database), active(false) {}

    bool begin() {
        char* errorMessage = nullptr;
        int result = sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, &errorMessage);
        if (result != SQLITE_OK) {
            sqlite3_free(errorMessage);
            return false;
        }
        active = true;
        return true;
    }

    bool commit() {
        if (!active) return false;
        
        char* errorMessage = nullptr;
        int result = sqlite3_exec(db, "COMMIT", nullptr, nullptr, &errorMessage);
        if (result != SQLITE_OK) {
            sqlite3_free(errorMessage);
            return false;
        }
        active = false;
        return true;
    }

    bool rollback() {
        if (!active) return false;
        
        char* errorMessage = nullptr;
        int result = sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, &errorMessage);
        if (result != SQLITE_OK) {
            sqlite3_free(errorMessage);
            return false;
        }
        active = false;
        return true;
    }

    bool isActive() const {
        return active;
    }
};

class PreparedStatementCache {
private:
    struct CachedStatement {
        sqlite3_stmt* stmt;
        time_t lastUsed;
        int useCount;
    };

    std::unordered_map<std::string, CachedStatement> cache;
    size_t maxSize;
    std::mutex cacheMutex;

public:
    PreparedStatementCache(size_t max = 100) : maxSize(max) {}

    ~PreparedStatementCache() {
        clear();
    }

    sqlite3_stmt* get(sqlite3* db, const std::string& sql) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        
        auto it = cache.find(sql);
        if (it != cache.end()) {
            it->second.lastUsed = time(nullptr);
            it->second.useCount++;
            return it->second.stmt;
        }

        if (cache.size() >= maxSize) {
            evictOldest();
        }

        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            cache[sql] = {stmt, time(nullptr), 1};
            return stmt;
        }

        return nullptr;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(cacheMutex);
        for (auto& pair : cache) {
            sqlite3_finalize(pair.second.stmt);
        }
        cache.clear();
    }

private:
    void evictOldest() {
        auto oldest = cache.begin();
        for (auto it = cache.begin(); it != cache.end(); ++it) {
            if (it->second.lastUsed < oldest->second.lastUsed) {
                oldest = it;
            }
        }
        if (oldest != cache.end()) {
            sqlite3_finalize(oldest->second.stmt);
            cache.erase(oldest);
        }
    }
};

class ConnectionPool {
private:
    struct PoolConnection {
        sqlite3* db;
        bool inUse;
        time_t lastUsed;
    };

    std::string databasePath;
    std::vector<PoolConnection> connections;
    size_t maxConnections;
    std::mutex poolMutex;
    std::condition_variable poolCondition;

public:
    ConnectionPool(const std::string& path, size_t max = 5) 
        : databasePath(path), maxConnections(max) {}

    ~ConnectionPool() {
        closeAll();
    }

    sqlite3* getConnection() {
        std::unique_lock<std::mutex> lock(poolMutex);
        
        for (auto& conn : connections) {
            if (!conn.inUse) {
                conn.inUse = true;
                conn.lastUsed = time(nullptr);
                return conn.db;
            }
        }

        if (connections.size() < maxConnections) {
            sqlite3* newDb = nullptr;
            int result = sqlite3_open(databasePath.c_str(), &newDb);
            if (result == SQLITE_OK) {
                connections.push_back({newDb, true, time(nullptr)});
                return newDb;
            }
        }

        poolCondition.wait(lock, [this]() {
            for (const auto& conn : connections) {
                if (!conn.inUse) return true;
            }
            return false;
        });

        for (auto& conn : connections) {
            if (!conn.inUse) {
                conn.inUse = true;
                conn.lastUsed = time(nullptr);
                return conn.db;
            }
        }

        return nullptr;
    }

    void returnConnection(sqlite3* db) {
        std::lock_guard<std::mutex> lock(poolMutex);
        for (auto& conn : connections) {
            if (conn.db == db) {
                conn.inUse = false;
                conn.lastUsed = time(nullptr);
                break;
            }
        }
        poolCondition.notify_one();
    }

    void closeAll() {
        std::lock_guard<std::mutex> lock(poolMutex);
        for (auto& conn : connections) {
            sqlite3_close(conn.db);
        }
        connections.clear();
    }
};

class AsyncTaskQueue {
private:
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::vector<std::thread> workers;
    std::atomic<bool> stop;

public:
    AsyncTaskQueue(size_t numThreads = 2) : stop(false) {
        for (size_t i = 0; i < numThreads; ++i) {
            workers.emplace_back([this]() { workerThread(); });
        }
    }

    ~AsyncTaskQueue() {
        stop = true;
        queueCondition.notify_all();
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    template<typename F>
    void enqueue(F&& task) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            tasks.emplace(std::forward<F>(task));
        }
        queueCondition.notify_one();
    }

private:
    void workerThread() {
        while (!stop) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCondition.wait(lock, [this]() { return stop || !tasks.empty(); });
                
                if (stop && tasks.empty()) return;
                
                if (!tasks.empty()) {
                    task = std::move(tasks.front());
                    tasks.pop();
                }
            }
            
            if (task) {
                task();
            }
        }
    }
};

class DatabaseEngine : public MetricsBase {
private:
    sqlite3* db;
    std::string databasePath;
    bool isConnected;
    std::unique_ptr<DatabaseTransaction> currentTransaction;
    std::unique_ptr<PreparedStatementCache> statementCache;
    std::unique_ptr<ConnectionPool> connectionPool;
    std::unique_ptr<AsyncTaskQueue> taskQueue;
    std::vector<std::function<void(const std::string&)>> changeCallbacks;
    std::mutex callbackMutex;
    bool useEncryption;
    std::string encryptionKey;
    bool metrics_enabled_;

    static int callback(void* data, int argc, char** argv, char** azColName) {
        DatabaseResult* result = static_cast<DatabaseResult*>(data);
        
        std::unordered_map<std::string, std::string> row;
        for (int i = 0; i < argc; i++) {
            std::string columnName = azColName[i] ? azColName[i] : "";
            std::string value = argv[i] ? argv[i] : "";
            row[columnName] = value;
        }
        result->data.push_back(row);
        
        return 0;
    }

    void notifyChangeCallbacks(const std::string& table) {
        std::lock_guard<std::mutex> lock(callbackMutex);
        for (const auto& callback : changeCallbacks) {
            callback(table);
        }
    }

    bool applyEncryption() {
        if (!useEncryption || encryptionKey.empty()) return true;
        return true;
    }

public:
    DatabaseEngine() : MetricsBase("DATABASE_ENGINE"), db(nullptr), isConnected(false), useEncryption(false), metrics_enabled_(true) {}

    ~DatabaseEngine() {
        close();
    }

    void enableMetrics(bool enabled) {
        metrics_enabled_ = enabled;
        MetricsBase::enableMetrics(enabled);
    }

    bool isMetricsEnabled() const {
        return metrics_enabled_;
    }

    bool open(const std::string& path, const std::string& key = "") {
        if (!metrics_enabled_) {
            if (isConnected) close();
            databasePath = path;
            useEncryption = !key.empty();
            encryptionKey = key;
            int result = sqlite3_open(databasePath.c_str(), &db);
            if (result != SQLITE_OK) {
                isConnected = false;
                return false;
            }
            if (useEncryption && !applyEncryption()) {
                sqlite3_close(db);
                db = nullptr;
                return false;
            }
            statementCache = std::make_unique<PreparedStatementCache>();
            connectionPool = std::make_unique<ConnectionPool>(path);
            taskQueue = std::make_unique<AsyncTaskQueue>();
            isConnected = true;
            return true;
        }

        return measure("open_database", [&]() {
            if (isConnected) {
                close();
            }

            databasePath = path;
            useEncryption = !key.empty();
            encryptionKey = key;

            int result = sqlite3_open(databasePath.c_str(), &db);

            if (result != SQLITE_OK) {
                isConnected = false;
                logError("open_database", "Failed to open database", 3001, {{"path", path}, {"error", sqlite3_errmsg(db)}});
                return false;
            }

            if (useEncryption) {
                if (!applyEncryption()) {
                    sqlite3_close(db);
                    db = nullptr;
                    logError("open_database", "Failed to apply encryption", 3002, {{"path", path}});
                    return false;
                }
            }

            statementCache = std::make_unique<PreparedStatementCache>();
            connectionPool = std::make_unique<ConnectionPool>(path);
            taskQueue = std::make_unique<AsyncTaskQueue>();

            isConnected = true;
            
            sqlite3_create_function(db, "android_compress", 1, SQLITE_UTF8, nullptr, 
                [](sqlite3_context* context, int argc, sqlite3_value** argv) {
                    if (argc == 1) {
                        const void* data = sqlite3_value_blob(argv[0]);
                        int size = sqlite3_value_bytes(argv[0]);
                        sqlite3_result_blob(context, data, size, SQLITE_TRANSIENT);
                    }
                }, nullptr, nullptr);

            logInfo("open_database", "Database opened successfully", {{"path", path}, {"encrypted", useEncryption}});
            return true;
        }, {{"path", path}, {"encrypted", !key.empty()}});
    }

    void close() {
        if (!metrics_enabled_) {
            if (db) {
                if (currentTransaction && currentTransaction->isActive()) {
                    currentTransaction->rollback();
                }
                if (statementCache) {
                    statementCache->clear();
                }
                sqlite3_close(db);
                db = nullptr;
            }
            isConnected = false;
            return;
        }

        measure("close_database", [&]() {
            if (db) {
                if (currentTransaction && currentTransaction->isActive()) {
                    currentTransaction->rollback();
                    logWarning("close_database", "Active transaction rolled back during close");
                }
                if (statementCache) {
                    statementCache->clear();
                }
                sqlite3_close(db);
                db = nullptr;
                logInfo("close_database", "Database closed successfully", {{"path", databasePath}});
            }
            isConnected = false;
        }, {{"path", databasePath}});
    }

    bool isOpen() const {
        return isConnected;
    }

    DatabaseResult executeQuery(const std::string& query) {
        if (!metrics_enabled_) {
            DatabaseResult result;
            result.query = query;
            if (!isConnected) {
                result.success = false;
                result.message = "Database not connected";
                return result;
            }
            char* errorMessage = nullptr;
            int rc = sqlite3_exec(db, query.c_str(), callback, &result, &errorMessage);
            if (rc != SQLITE_OK) {
                result.success = false;
                result.message = errorMessage ? errorMessage : "Unknown error";
                sqlite3_free(errorMessage);
            } else {
                result.success = true;
                result.affectedRows = sqlite3_changes(db);
                result.lastInsertId = sqlite3_last_insert_rowid(db);
            }
            return result;
        }

        return measure("execute_query", [&]() -> DatabaseResult {
            DatabaseResult result;
            result.query = query;

            if (!isConnected) {
                result.success = false;
                result.message = "Database not connected";
                logError("execute_query", "Database not connected", 3003, {{"query", query}});
                return result;
            }

            char* errorMessage = nullptr;
            int rc = sqlite3_exec(db, query.c_str(), callback, &result, &errorMessage);

            if (rc != SQLITE_OK) {
                result.success = false;
                result.message = errorMessage ? errorMessage : "Unknown error";
                logError("execute_query", "Query execution failed", 3004, 
                        {{"query", query}, {"error", result.message}});
                sqlite3_free(errorMessage);
            } else {
                result.success = true;
                result.affectedRows = sqlite3_changes(db);
                result.lastInsertId = sqlite3_last_insert_rowid(db);
                logInfo("execute_query", "Query executed successfully",
                       {{"query", query}, {"affected_rows", result.affectedRows}, 
                        {"result_rows", result.data.size()}});
            }

            return result;
        }, {{"query", query}});
    }

    DatabaseResult executePrepared(const std::string& query, const std::vector<std::string>& params) {
        if (!metrics_enabled_) {
            DatabaseResult result;
            result.query = query;
            if (!isConnected) {
                result.success = false;
                result.message = "Database not connected";
                return result;
            }
            sqlite3_stmt* stmt = statementCache->get(db, query);
            if (!stmt) {
                int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
                if (rc != SQLITE_OK) {
                    result.success = false;
                    result.message = sqlite3_errmsg(db);
                    return result;
                }
            }
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            for (size_t i = 0; i < params.size(); i++) {
                sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
            }
            while ((sqlite3_step(stmt)) == SQLITE_ROW) {
                std::unordered_map<std::string, std::string> row;
                int columnCount = sqlite3_column_count(stmt);
                for (int i = 0; i < columnCount; i++) {
                    std::string columnName = sqlite3_column_name(stmt, i);
                    const unsigned char* value = sqlite3_column_text(stmt, i);
                    std::string stringValue = value ? reinterpret_cast<const char*>(value) : "";
                    row[columnName] = stringValue;
                }
                result.data.push_back(row);
            }
            result.success = true;
            result.affectedRows = sqlite3_changes(db);
            result.lastInsertId = sqlite3_last_insert_rowid(db);
            return result;
        }

        return measure("execute_prepared", [&]() -> DatabaseResult {
            DatabaseResult result;
            result.query = query;

            if (!isConnected) {
                result.success = false;
                result.message = "Database not connected";
                logError("execute_prepared", "Database not connected", 3005, {{"query", query}});
                return result;
            }

            sqlite3_stmt* stmt = statementCache->get(db, query);
            if (!stmt) {
                int rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
                if (rc != SQLITE_OK) {
                    result.success = false;
                    result.message = sqlite3_errmsg(db);
                    logError("execute_prepared", "Failed to prepare statement", 3006,
                            {{"query", query}, {"error", result.message}});
                    return result;
                }
            }

            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);

            for (size_t i = 0; i < params.size(); i++) {
                sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
            }

            int rc;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                std::unordered_map<std::string, std::string> row;
                int columnCount = sqlite3_column_count(stmt);
                
                for (int i = 0; i < columnCount; i++) {
                    std::string columnName = sqlite3_column_name(stmt, i);
                    const unsigned char* value = sqlite3_column_text(stmt, i);
                    std::string stringValue = value ? reinterpret_cast<const char*>(value) : "";
                    row[columnName] = stringValue;
                }
                result.data.push_back(row);
            }

            if (rc != SQLITE_DONE) {
                result.success = false;
                result.message = sqlite3_errmsg(db);
                logError("execute_prepared", "Prepared statement execution failed", 3007,
                        {{"query", query}, {"error", result.message}});
            } else {
                result.success = true;
                result.affectedRows = sqlite3_changes(db);
                result.lastInsertId = sqlite3_last_insert_rowid(db);
                logInfo("execute_prepared", "Prepared statement executed successfully",
                       {{"query", query}, {"param_count", params.size()}, 
                        {"result_rows", result.data.size()}});
            }

            return result;
        }, {{"query", query}, {"param_count", params.size()}});
    }

    bool createTable(const DatabaseTable& table) {
        if (!metrics_enabled_) {
            std::stringstream query;
            query << "CREATE TABLE IF NOT EXISTS " << table.name << " (";
            for (size_t i = 0; i < table.columns.size(); i++) {
                const DatabaseColumn& column = table.columns[i];
                if (i > 0) query << ", ";
                query << column.name << " " << column.type;
                if (column.primaryKey) query << " PRIMARY KEY";
                if (column.autoIncrement) query << " AUTOINCREMENT";
                if (column.notNull) query << " NOT NULL";
                if (!column.defaultValue.empty()) query << " DEFAULT " << column.defaultValue;
            }
            if (!table.conflictResolution.empty()) {
                query << ") " << table.conflictResolution;
            } else {
                query << ")";
            }
            DatabaseResult result = executeQuery(query.str());
            for (const auto& column : table.columns) {
                if (column.indexed) {
                    createIndex(table.name + "_" + column.name + "_idx", table.name, {column.name});
                }
            }
            return result.success;
        }

        return measure("create_table", [&]() {
            std::stringstream query;
            query << "CREATE TABLE IF NOT EXISTS " << table.name << " (";

            for (size_t i = 0; i < table.columns.size(); i++) {
                const DatabaseColumn& column = table.columns[i];
                if (i > 0) query << ", ";
                query << column.name << " " << column.type;

                if (column.primaryKey) query << " PRIMARY KEY";
                if (column.autoIncrement) query << " AUTOINCREMENT";
                if (column.notNull) query << " NOT NULL";
                if (!column.defaultValue.empty()) query << " DEFAULT " << column.defaultValue;
            }

            if (!table.conflictResolution.empty()) {
                query << ") " << table.conflictResolution;
            } else {
                query << ")";
            }

            DatabaseResult result = executeQuery(query.str());
            
            int index_count = 0;
            for (const auto& column : table.columns) {
                if (column.indexed) {
                    if (createIndex(table.name + "_" + column.name + "_idx", table.name, {column.name})) {
                        index_count++;
                    }
                }
            }

            if (result.success) {
                logInfo("create_table", "Table created successfully",
                       {{"table_name", table.name}, {"column_count", table.columns.size()}, {"index_count", index_count}});
            } else {
                logError("create_table", "Failed to create table", 3008,
                        {{"table_name", table.name}, {"error", result.message}});
            }
            
            return result.success;
        }, {{"table_name", table.name}, {"column_count", table.columns.size()}});
    }

    bool createIndex(const std::string& indexName, const std::string& tableName, 
                    const std::vector<std::string>& columns) {
        if (!metrics_enabled_) {
            std::stringstream query;
            query << "CREATE INDEX IF NOT EXISTS " << indexName << " ON " << tableName << " (";
            for (size_t i = 0; i < columns.size(); i++) {
                if (i > 0) query << ", ";
                query << columns[i];
            }
            query << ")";
            DatabaseResult result = executeQuery(query.str());
            return result.success;
        }

        return measure("create_index", [&]() {
            std::stringstream query;
            query << "CREATE INDEX IF NOT EXISTS " << indexName << " ON " << tableName << " (";
            
            for (size_t i = 0; i < columns.size(); i++) {
                if (i > 0) query << ", ";
                query << columns[i];
            }
            query << ")";

            DatabaseResult result = executeQuery(query.str());
            if (result.success) {
                logInfo("create_index", "Index created successfully",
                       {{"index_name", indexName}, {"table_name", tableName}, {"columns", columns.size()}});
            } else {
                logError("create_index", "Failed to create index", 3009,
                        {{"index_name", indexName}, {"table_name", tableName}, {"error", result.message}});
            }
            return result.success;
        }, {{"index_name", indexName}, {"table_name", tableName}, {"column_count", columns.size()}});
    }

    bool dropTable(const std::string& tableName) {
        if (!metrics_enabled_) {
            std::string query = "DROP TABLE IF EXISTS " + tableName;
            DatabaseResult result = executeQuery(query);
            if (result.success) {
                notifyChangeCallbacks(tableName);
            }
            return result.success;
        }

        return measure("drop_table", [&]() {
            std::string query = "DROP TABLE IF EXISTS " + tableName;
            DatabaseResult result = executeQuery(query);
            if (result.success) {
                notifyChangeCallbacks(tableName);
                logInfo("drop_table", "Table dropped successfully", {{"table_name", tableName}});
            } else {
                logError("drop_table", "Failed to drop table", 3010,
                        {{"table_name", tableName}, {"error", result.message}});
            }
            return result.success;
        }, {{"table_name", tableName}});
    }

    bool addColumn(const std::string& tableName, const DatabaseColumn& column) {
        if (!metrics_enabled_) {
            std::stringstream query;
            query << "ALTER TABLE " << tableName << " ADD COLUMN " << column.name << " " << column.type;
            if (column.primaryKey) query << " PRIMARY KEY";
            if (column.autoIncrement) query << " AUTOINCREMENT";
            if (column.notNull) query << " NOT NULL";
            if (!column.defaultValue.empty()) query << " DEFAULT " << column.defaultValue;
            DatabaseResult result = executeQuery(query.str());
            return result.success;
        }

        return measure("add_column", [&]() {
            std::stringstream query;
            query << "ALTER TABLE " << tableName << " ADD COLUMN " << column.name << " " << column.type;

            if (column.primaryKey) query << " PRIMARY KEY";
            if (column.autoIncrement) query << " AUTOINCREMENT";
            if (column.notNull) query << " NOT NULL";
            if (!column.defaultValue.empty()) query << " DEFAULT " << column.defaultValue;

            DatabaseResult result = executeQuery(query.str());
            if (result.success) {
                logInfo("add_column", "Column added successfully",
                       {{"table_name", tableName}, {"column_name", column.name}, {"column_type", column.type}});
            } else {
                logError("add_column", "Failed to add column", 3011,
                        {{"table_name", tableName}, {"column_name", column.name}, {"error", result.message}});
            }
            return result.success;
        }, {{"table_name", tableName}, {"column_name", column.name}, {"column_type", column.type}});
    }

    std::vector<std::string> getTableNames() {
        if (!metrics_enabled_) {
            std::vector<std::string> tables;
            DatabaseResult result = executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            );
            if (result.success) {
                for (const auto& row : result.data) {
                    tables.push_back(row.at("name"));
                }
            }
            return tables;
        }

        return measure("get_table_names", [&]() -> std::vector<std::string> {
            std::vector<std::string> tables;
            DatabaseResult result = executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            );

            if (result.success) {
                for (const auto& row : result.data) {
                    tables.push_back(row.at("name"));
                }
                logInfo("get_table_names", "Table names retrieved successfully",
                       {{"table_count", tables.size()}});
            } else {
                logError("get_table_names", "Failed to get table names", 3012,
                        {{"error", result.message}});
            }

            return tables;
        });
    }

    std::vector<DatabaseColumn> getTableSchema(const std::string& tableName) {
        if (!metrics_enabled_) {
            std::vector<DatabaseColumn> columns;
            DatabaseResult result = executeQuery("PRAGMA table_info(" + tableName + ")");
            if (result.success) {
                for (const auto& row : result.data) {
                    DatabaseColumn column(row.at("name"), row.at("type"));
                    column.notNull = (row.at("notnull") == "1");
                    column.primaryKey = (row.at("pk") == "1");
                    if (row.find("dflt_value") != row.end() && !row.at("dflt_value").empty()) {
                        column.defaultValue = row.at("dflt_value");
                    }
                    columns.push_back(column);
                }
            }
            return columns;
        }

        return measure("get_table_schema", [&]() -> std::vector<DatabaseColumn> {
            std::vector<DatabaseColumn> columns;
            DatabaseResult result = executeQuery("PRAGMA table_info(" + tableName + ")");

            if (result.success) {
                for (const auto& row : result.data) {
                    DatabaseColumn column(row.at("name"), row.at("type"));
                    column.notNull = (row.at("notnull") == "1");
                    column.primaryKey = (row.at("pk") == "1");
                    if (row.find("dflt_value") != row.end() && !row.at("dflt_value").empty()) {
                        column.defaultValue = row.at("dflt_value");
                    }
                    columns.push_back(column);
                }
                logInfo("get_table_schema", "Table schema retrieved successfully",
                       {{"table_name", tableName}, {"column_count", columns.size()}});
            } else {
                logError("get_table_schema", "Failed to get table schema", 3013,
                        {{"table_name", tableName}, {"error", result.message}});
            }

            return columns;
        }, {{"table_name", tableName}});
    }

    QueryBuilder query() {
        return QueryBuilder();
    }

    DatabaseResult select(const std::string& table, const std::vector<std::string>& columns = {"*"}, 
                         const std::string& where = "", const std::string& orderBy = "", 
                         int limit = -1, int offset = -1) {
        if (!metrics_enabled_) {
            QueryBuilder qb = query().select(columns).from(table);
            if (!where.empty()) qb.where(where);
            if (!orderBy.empty()) qb.orderBy(orderBy);
            if (limit > 0) qb.limit(limit);
            if (offset > 0) qb.offset(offset);
            return executeQuery(qb.build());
        }

        return measure("select", [&]() -> DatabaseResult {
            QueryBuilder qb = query().select(columns).from(table);
            
            if (!where.empty()) qb.where(where);
            if (!orderBy.empty()) qb.orderBy(orderBy);
            if (limit > 0) qb.limit(limit);
            if (offset > 0) qb.offset(offset);
            
            DatabaseResult result = executeQuery(qb.build());
            
            if (result.success) {
                logInfo("select", "Select query executed successfully",
                       {{"table", table}, {"result_rows", result.data.size()}, 
                        {"limit", limit}, {"offset", offset}});
            }
            
            return result;
        }, {{"table", table}, {"column_count", columns.size()}, {"has_where", !where.empty()}, 
            {"limit", limit}, {"offset", offset}});
    }

    DatabaseResult insert(const std::string& table, const std::unordered_map<std::string, std::string>& values, 
                         const std::string& conflictResolution = "") {
        if (!metrics_enabled_) {
            std::vector<std::string> columns;
            std::vector<std::string> valuePlaceholders;
            for (const auto& pair : values) {
                columns.push_back(pair.first);
                valuePlaceholders.push_back("'" + pair.second + "'");
            }
            QueryBuilder qb = query().insertInto(table, columns).values(valuePlaceholders);
            if (!conflictResolution.empty()) {
                qb.onConflict(conflictResolution);
            }
            DatabaseResult result = executeQuery(qb.build());
            if (result.success) {
                notifyChangeCallbacks(table);
            }
            return result;
        }

        return measure("insert", [&]() -> DatabaseResult {
            std::vector<std::string> columns;
            std::vector<std::string> valuePlaceholders;
            
            for (const auto& pair : values) {
                columns.push_back(pair.first);
                valuePlaceholders.push_back("'" + pair.second + "'");
            }
            
            QueryBuilder qb = query().insertInto(table, columns).values(valuePlaceholders);
            if (!conflictResolution.empty()) {
                qb.onConflict(conflictResolution);
            }
            
            DatabaseResult result = executeQuery(qb.build());
            if (result.success) {
                notifyChangeCallbacks(table);
                logInfo("insert", "Insert query executed successfully",
                       {{"table", table}, {"columns", columns.size()}, 
                        {"insert_id", result.lastInsertId}});
            } else {
                logError("insert", "Failed to execute insert", 3014,
                        {{"table", table}, {"error", result.message}});
            }
            return result;
        }, {{"table", table}, {"column_count", values.size()}, {"conflict_resolution", conflictResolution}});
    }

    DatabaseResult update(const std::string& table, const std::unordered_map<std::string, std::string>& values, 
                         const std::string& where = "") {
        if (!metrics_enabled_) {
            QueryBuilder qb = query().update(table);
            for (const auto& pair : values) {
                qb.set(pair.first, "'" + pair.second + "'");
            }
            if (!where.empty()) qb.where(where);
            DatabaseResult result = executeQuery(qb.build());
            if (result.success) {
                notifyChangeCallbacks(table);
            }
            return result;
        }

        return measure("update", [&]() -> DatabaseResult {
            QueryBuilder qb = query().update(table);
            
            for (const auto& pair : values) {
                qb.set(pair.first, "'" + pair.second + "'");
            }
            
            if (!where.empty()) qb.where(where);
            
            DatabaseResult result = executeQuery(qb.build());
            if (result.success) {
                notifyChangeCallbacks(table);
                logInfo("update", "Update query executed successfully",
                       {{"table", table}, {"updated_rows", result.affectedRows}, 
                        {"has_where", !where.empty()}});
            } else {
                logError("update", "Failed to execute update", 3015,
                        {{"table", table}, {"error", result.message}});
            }
            return result;
        }, {{"table", table}, {"update_count", values.size()}, {"has_where", !where.empty()}});
    }

    DatabaseResult deleteRows(const std::string& table, const std::string& where = "") {
        if (!metrics_enabled_) {
            QueryBuilder qb = query().deleteFrom(table);
            if (!where.empty()) qb.where(where);
            DatabaseResult result = executeQuery(qb.build());
            if (result.success) {
                notifyChangeCallbacks(table);
            }
            return result;
        }

        return measure("delete_rows", [&]() -> DatabaseResult {
            QueryBuilder qb = query().deleteFrom(table);
            
            if (!where.empty()) qb.where(where);
            
            DatabaseResult result = executeQuery(qb.build());
            if (result.success) {
                notifyChangeCallbacks(table);
                logInfo("delete_rows", "Delete query executed successfully",
                       {{"table", table}, {"deleted_rows", result.affectedRows}, 
                        {"has_where", !where.empty()}});
            } else {
                logError("delete_rows", "Failed to execute delete", 3016,
                        {{"table", table}, {"error", result.message}});
            }
            return result;
        }, {{"table", table}, {"has_where", !where.empty()}});
    }

    bool beginTransaction() {
        if (!metrics_enabled_) {
            if (!currentTransaction) {
                currentTransaction = std::make_unique<DatabaseTransaction>(db);
            }
            return currentTransaction->begin();
        }

        return measure("begin_transaction", [&]() {
            if (!currentTransaction) {
                currentTransaction = std::make_unique<DatabaseTransaction>(db);
            }
            bool success = currentTransaction->begin();
            if (success) {
                logInfo("begin_transaction", "Transaction started successfully");
            } else {
                logError("begin_transaction", "Failed to start transaction", 3017);
            }
            return success;
        });
    }

    bool commitTransaction() {
        if (!metrics_enabled_) {
            if (currentTransaction && currentTransaction->isActive()) {
                bool result = currentTransaction->commit();
                currentTransaction.reset();
                return result;
            }
            return false;
        }

        return measure("commit_transaction", [&]() {
            if (currentTransaction && currentTransaction->isActive()) {
                bool result = currentTransaction->commit();
                currentTransaction.reset();
                if (result) {
                    logInfo("commit_transaction", "Transaction committed successfully");
                } else {
                    logError("commit_transaction", "Failed to commit transaction", 3018);
                }
                return result;
            }
            logWarning("commit_transaction", "No active transaction to commit");
            return false;
        });
    }

    bool rollbackTransaction() {
        if (!metrics_enabled_) {
            if (currentTransaction && currentTransaction->isActive()) {
                bool result = currentTransaction->rollback();
                currentTransaction.reset();
                return result;
            }
            return false;
        }

        return measure("rollback_transaction", [&]() {
            if (currentTransaction && currentTransaction->isActive()) {
                bool result = currentTransaction->rollback();
                currentTransaction.reset();
                if (result) {
                    logInfo("rollback_transaction", "Transaction rolled back successfully");
                } else {
                    logError("rollback_transaction", "Failed to rollback transaction", 3019);
                }
                return result;
            }
            logWarning("rollback_transaction", "No active transaction to rollback");
            return false;
        });
    }

    bool backupDatabase(const std::string& backupPath) {
        if (!metrics_enabled_) {
            if (!isConnected) return false;
            sqlite3* backupDb;
            int rc = sqlite3_open(backupPath.c_str(), &backupDb);
            if (rc != SQLITE_OK) return false;
            sqlite3_backup* backup = sqlite3_backup_init(backupDb, "main", db, "main");
            if (!backup) {
                sqlite3_close(backupDb);
                return false;
            }
            rc = sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);
            bool success = (rc == SQLITE_DONE);
            sqlite3_close(backupDb);
            return success;
        }

        return measure("backup_database", [&]() {
            if (!isConnected) {
                logError("backup_database", "Database not connected", 3020);
                return false;
            }

            sqlite3* backupDb;
            int rc = sqlite3_open(backupPath.c_str(), &backupDb);
            if (rc != SQLITE_OK) {
                logError("backup_database", "Failed to open backup database", 3021, {{"backup_path", backupPath}});
                return false;
            }

            sqlite3_backup* backup = sqlite3_backup_init(backupDb, "main", db, "main");
            if (!backup) {
                sqlite3_close(backupDb);
                logError("backup_database", "Failed to initialize backup", 3022, {{"backup_path", backupPath}});
                return false;
            }

            rc = sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);

            bool success = (rc == SQLITE_DONE);
            sqlite3_close(backupDb);

            if (success) {
                logInfo("backup_database", "Database backup completed successfully",
                       {{"backup_path", backupPath}});
            } else {
                logError("backup_database", "Database backup failed", 3023, {{"backup_path", backupPath}});
            }

            return success;
        }, {{"backup_path", backupPath}});
    }

    bool vacuum() {
        if (!metrics_enabled_) {
            DatabaseResult result = executeQuery("VACUUM");
            return result.success;
        }

        return measure("vacuum", [&]() {
            DatabaseResult result = executeQuery("VACUUM");
            if (result.success) {
                logInfo("vacuum", "Database vacuum completed successfully");
            } else {
                logError("vacuum", "Database vacuum failed", 3024, {{"error", result.message}});
            }
            return result.success;
        });
    }

    int getLastInsertRowId() const {
        return sqlite3_last_insert_rowid(db);
    }

    int getTotalChanges() const {
        return sqlite3_total_changes(db);
    }

    std::string getError() const {
        if (db) {
            return sqlite3_errmsg(db);
        }
        return "Database not connected";
    }

    bool tableExists(const std::string& tableName) {
        if (!metrics_enabled_) {
            DatabaseResult result = executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='" + tableName + "'"
            );
            return result.success && !result.data.empty();
        }

        return measure("table_exists", [&]() {
            DatabaseResult result = executeQuery(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='" + tableName + "'"
            );
            bool exists = result.success && !result.data.empty();
            logDebug("table_exists", exists ? "Table exists" : "Table does not exist", {{"table_name", tableName}});
            return exists;
        }, {{"table_name", tableName}});
    }

    DatabaseResult rawQuery(const std::string& sql) {
        return executeQuery(sql);
    }

    bool executeScript(const std::string& sqlScript) {
        if (!metrics_enabled_) {
            if (!isConnected) return false;
            char* errorMessage = nullptr;
            int rc = sqlite3_exec(db, sqlScript.c_str(), nullptr, nullptr, &errorMessage);
            if (rc != SQLITE_OK) {
                if (errorMessage) sqlite3_free(errorMessage);
                return false;
            }
            return true;
        }

        return measure("execute_script", [&]() {
            if (!isConnected) {
                logError("execute_script", "Database not connected", 3025);
                return false;
            }

            char* errorMessage = nullptr;
            int rc = sqlite3_exec(db, sqlScript.c_str(), nullptr, nullptr, &errorMessage);

            if (rc != SQLITE_OK) {
                std::string error = errorMessage ? errorMessage : "Unknown error";
                logError("execute_script", "Script execution failed", 3026, {{"error", error}});
                if (errorMessage) sqlite3_free(errorMessage);
                return false;
            }

            logInfo("execute_script", "SQL script executed successfully",
                   {{"script_length", sqlScript.length()}});
            return true;
        }, {{"script_length", sqlScript.length()}});
    }

    void registerChangeCallback(std::function<void(const std::string&)> callback) {
        std::lock_guard<std::mutex> lock(callbackMutex);
        changeCallbacks.push_back(callback);
        if (metrics_enabled_) {
            logInfo("register_change_callback", "Change callback registered");
        }
    }

    void unregisterChangeCallbacks() {
        std::lock_guard<std::mutex> lock(callbackMutex);
        changeCallbacks.clear();
        if (metrics_enabled_) {
            logInfo("unregister_change_callbacks", "All change callbacks unregistered");
        }
    }

    DatabaseResult fullTextSearch(const std::string& table, const std::string& searchTerm, 
                                 const std::vector<std::string>& columns) {
        if (!metrics_enabled_) {
            std::stringstream query;
            query << "SELECT * FROM " << table << " WHERE ";
            for (size_t i = 0; i < columns.size(); i++) {
                if (i > 0) query << " OR ";
                query << columns[i] << " MATCH ?";
            }
            return executePrepared(query.str(), {searchTerm});
        }

        return measure("full_text_search", [&]() -> DatabaseResult {
            std::stringstream query;
            query << "SELECT * FROM " << table << " WHERE ";
            
            for (size_t i = 0; i < columns.size(); i++) {
                if (i > 0) query << " OR ";
                query << columns[i] << " MATCH ?";
            }
            
            DatabaseResult result = executePrepared(query.str(), {searchTerm});
            
            if (result.success) {
                logInfo("full_text_search", "Full text search completed",
                       {{"table", table}, {"search_term", searchTerm}, 
                        {"result_count", result.data.size()}, {"column_count", columns.size()}});
            } else {
                logError("full_text_search", "Full text search failed", 3027,
                        {{"table", table}, {"search_term", searchTerm}, {"error", result.message}});
            }
            
            return result;
        }, {{"table", table}, {"search_term", searchTerm}, {"column_count", columns.size()}});
    }

    bool enableWALMode() {
        if (!metrics_enabled_) {
            DatabaseResult result = executeQuery("PRAGMA journal_mode=WAL");
            return result.success && !result.data.empty() && result.data[0].begin()->second == "wal";
        }

        return measure("enable_wal_mode", [&]() {
            DatabaseResult result = executeQuery("PRAGMA journal_mode=WAL");
            bool success = result.success && !result.data.empty() && result.data[0].begin()->second == "wal";
            if (success) {
                logInfo("enable_wal_mode", "WAL mode enabled successfully");
            } else {
                logError("enable_wal_mode", "Failed to enable WAL mode", 3028);
            }
            return success;
        });
    }

    bool setSynchronousMode(const std::string& mode) {
        if (!metrics_enabled_) {
            DatabaseResult result = executeQuery("PRAGMA synchronous=" + mode);
            return result.success;
        }

        return measure("set_synchronous_mode", [&]() {
            DatabaseResult result = executeQuery("PRAGMA synchronous=" + mode);
            if (result.success) {
                logInfo("set_synchronous_mode", "Synchronous mode set successfully", {{"mode", mode}});
            } else {
                logError("set_synchronous_mode", "Failed to set synchronous mode", 3029, {{"mode", mode}});
            }
            return result.success;
        }, {{"mode", mode}});
    }

    bool setCacheSize(int size) {
        if (!metrics_enabled_) {
            DatabaseResult result = executeQuery("PRAGMA cache_size=" + std::to_string(size));
            return result.success;
        }

        return measure("set_cache_size", [&]() {
            DatabaseResult result = executeQuery("PRAGMA cache_size=" + std::to_string(size));
            if (result.success) {
                logInfo("set_cache_size", "Cache size set successfully", {{"size", size}});
            } else {
                logError("set_cache_size", "Failed to set cache size", 3030, {{"size", size}});
            }
            return result.success;
        }, {{"size", size}});
    }

    bool migrateSchema(const std::vector<std::string>& migrationScripts) {
        if (!metrics_enabled_) {
            if (!beginTransaction()) return false;
            try {
                for (const auto& script : migrationScripts) {
                    if (!executeScript(script)) {
                        rollbackTransaction();
                        return false;
                    }
                }
                return commitTransaction();
            } catch (...) {
                rollbackTransaction();
                return false;
            }
        }

        return measure("migrate_schema", [&]() {
            if (!beginTransaction()) {
                logError("migrate_schema", "Failed to begin migration transaction", 3031);
                return false;
            }

            try {
                for (size_t i = 0; i < migrationScripts.size(); i++) {
                    if (!executeScript(migrationScripts[i])) {
                        logError("migrate_schema", "Migration script failed", 3032, 
                                {{"script_index", i}, {"total_scripts", migrationScripts.size()}});
                        rollbackTransaction();
                        return false;
                    }
                }
                
                if (commitTransaction()) {
                    logInfo("migrate_schema", "Schema migration completed successfully",
                           {{"migration_count", migrationScripts.size()}});
                    return true;
                } else {
                    logError("migrate_schema", "Failed to commit migration transaction", 3033);
                    return false;
                }
            } catch (const std::exception& e) {
                logError("migrate_schema", "Migration exception occurred", 3034, {{"error", e.what()}});
                rollbackTransaction();
                return false;
            }
        }, {{"migration_count", migrationScripts.size()}});
    }

    void executeAsync(std::function<void()> task) {
        if (taskQueue) {
            if (metrics_enabled_) {
                logDebug("execute_async", "Async task enqueued");
            }
            taskQueue->enqueue(task);
        }
    }

    DatabaseResult paginatedQuery(const std::string& query, int page, int pageSize) {
        if (!metrics_enabled_) {
            int offset = (page - 1) * pageSize;
            std::string paginatedQuery = query + " LIMIT " + std::to_string(pageSize) + 
                                       " OFFSET " + std::to_string(offset);
            return executeQuery(paginatedQuery);
        }

        return measure("paginated_query", [&]() -> DatabaseResult {
            int offset = (page - 1) * pageSize;
            std::string paginatedQuery = query + " LIMIT " + std::to_string(pageSize) + 
                                       " OFFSET " + std::to_string(offset);
            DatabaseResult result = executeQuery(paginatedQuery);
            
            if (result.success) {
                logInfo("paginated_query", "Paginated query executed successfully",
                       {{"page", page}, {"page_size", pageSize}, {"result_count", result.data.size()}});
            }
            
            return result;
        }, {{"page", page}, {"page_size", pageSize}});
    }

    bool createTrigger(const std::string& triggerName, const std::string& tableName,
                      const std::string& triggerTime, const std::string& triggerEvent,
                      const std::string& triggerBody) {
        if (!metrics_enabled_) {
            std::stringstream query;
            query << "CREATE TRIGGER " << triggerName << " " << triggerTime 
                  << " " << triggerEvent << " ON " << tableName << " " << triggerBody;
            DatabaseResult result = executeQuery(query.str());
            return result.success;
        }

        return measure("create_trigger", [&]() {
            std::stringstream query;
            query << "CREATE TRIGGER " << triggerName << " " << triggerTime 
                  << " " << triggerEvent << " ON " << tableName << " " << triggerBody;
            
            DatabaseResult result = executeQuery(query.str());
            if (result.success) {
                logInfo("create_trigger", "Trigger created successfully",
                       {{"trigger_name", triggerName}, {"table_name", tableName}, 
                        {"trigger_event", triggerEvent}});
            } else {
                logError("create_trigger", "Failed to create trigger", 3035,
                        {{"trigger_name", triggerName}, {"table_name", tableName}, 
                         {"error", result.message}});
            }
            return result.success;
        }, {{"trigger_name", triggerName}, {"table_name", tableName}, {"trigger_event", triggerEvent}});
    }

    void registerCustomFunction(const std::string& name, int numArgs,
                               std::function<void(sqlite3_context*, int, sqlite3_value**)> func) {
        sqlite3_create_function(db, name.c_str(), numArgs, SQLITE_UTF8, 
            new std::function<void(sqlite3_context*, int, sqlite3_value**)>(func),
            [](sqlite3_context* context, int argc, sqlite3_value** argv) {
                void* ud = sqlite3_user_data(context);
                auto* func = static_cast<std::function<void(sqlite3_context*, int, sqlite3_value**)>*>(ud);
                (*func)(context, argc, argv);
            },
            nullptr,
            [](void* ud) { delete static_cast<std::function<void(sqlite3_context*, int, sqlite3_value**)>*>(ud); }
        );
        
        if (metrics_enabled_) {
            logInfo("register_custom_function", "Custom function registered", {{"function_name", name}, {"arg_count", numArgs}});
        }
    }

    bool optimizeDatabase() {
        if (!metrics_enabled_) {
            bool success = true;
            success &= executeQuery("PRAGMA optimize").success;
            success &= executeQuery("PRAGMA incremental_vacuum").success;
            success &= executeQuery("PRAGMA analysis_limit=400").success;
            return success;
        }

        return measure("optimize_database", [&]() {
            bool success = true;
            success &= executeQuery("PRAGMA optimize").success;
            success &= executeQuery("PRAGMA incremental_vacuum").success;
            success &= executeQuery("PRAGMA analysis_limit=400").success;
            
            if (success) {
                logInfo("optimize_database", "Database optimization completed successfully");
            } else {
                logError("optimize_database", "Database optimization failed", 3036);
            }
            return success;
        });
    }

    size_t getDatabaseSize() {
        if (!metrics_enabled_) {
            DatabaseResult result = executeQuery("PRAGMA page_count");
            if (result.success && !result.data.empty()) {
                size_t pageCount = std::stoul(result.data[0].begin()->second);
                result = executeQuery("PRAGMA page_size");
                if (result.success && !result.data.empty()) {
                    size_t pageSize = std::stoul(result.data[0].begin()->second);
                    return pageCount * pageSize;
                }
            }
            return 0;
        }

        return measure("get_database_size", [&]() -> size_t {
            DatabaseResult result = executeQuery("PRAGMA page_count");
            if (result.success && !result.data.empty()) {
                size_t pageCount = std::stoul(result.data[0].begin()->second);
                result = executeQuery("PRAGMA page_size");
                if (result.success && !result.data.empty()) {
                    size_t pageSize = std::stoul(result.data[0].begin()->second);
                    size_t totalSize = pageCount * pageSize;
                    logInfo("get_database_size", "Database size retrieved",
                           {{"size_bytes", totalSize}, {"page_count", pageCount}, {"page_size", pageSize}});
                    return totalSize;
                }
            }
            logError("get_database_size", "Failed to get database size", 3037);
            return 0;
        });
    }

    bool compactDatabase() {
        if (!metrics_enabled_) {
            return vacuum() && optimizeDatabase();
        }

        return measure("compact_database", [&]() {
            bool success = vacuum() && optimizeDatabase();
            if (success) {
                logInfo("compact_database", "Database compaction completed successfully");
            } else {
                logError("compact_database", "Database compaction failed", 3038);
            }
            return success;
        });
    }
};