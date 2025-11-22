#ifndef DATABASE_ENGINE_H
#define DATABASE_ENGINE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <sqlite3.h>

class DatabaseResult {
public:
    bool success;
    std::string message;
    std::vector<std::unordered_map<std::string, std::string>> data;
    int affectedRows;
    int lastInsertId;
    std::string query;

    DatabaseResult();
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

    DatabaseColumn(const std::string& colName, const std::string& colType);
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
    QueryBuilder();
    QueryBuilder& select(const std::vector<std::string>& columns = {"*"});
    QueryBuilder& from(const std::string& table);
    QueryBuilder& where(const std::string& condition);
    QueryBuilder& orderBy(const std::string& column, bool ascending = true);
    QueryBuilder& groupBy(const std::vector<std::string>& columns);
    QueryBuilder& having(const std::string& condition);
    QueryBuilder& limit(int limit);
    QueryBuilder& offset(int offset);
    QueryBuilder& update(const std::string& table);
    QueryBuilder& set(const std::string& column, const std::string& value);
    QueryBuilder& insertInto(const std::string& table, const std::vector<std::string>& columns);
    QueryBuilder& values(const std::vector<std::string>& values);
    QueryBuilder& onConflict(const std::string& resolution);
    QueryBuilder& deleteFrom(const std::string& table);
    std::string build();
};

class DatabaseTransaction {
private:
    sqlite3* db;
    bool active;

public:
    DatabaseTransaction(sqlite3* database);
    bool begin();
    bool commit();
    bool rollback();
    bool isActive() const;
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

    void evictOldest();

public:
    PreparedStatementCache(size_t max = 100);
    ~PreparedStatementCache();
    sqlite3_stmt* get(sqlite3* db, const std::string& sql);
    void clear();
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
    ConnectionPool(const std::string& path, size_t max = 5);
    ~ConnectionPool();
    sqlite3* getConnection();
    void returnConnection(sqlite3* db);
    void closeAll();
};

class AsyncTaskQueue {
private:
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::vector<std::thread> workers;
    std::atomic<bool> stop;

    void workerThread();

public:
    AsyncTaskQueue(size_t numThreads = 2);
    ~AsyncTaskQueue();

    template<typename F>
    void enqueue(F&& task);
};

class DatabaseEngine {
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

    static int callback(void* data, int argc, char** argv, char** azColName);
    void notifyChangeCallbacks(const std::string& table);
    bool applyEncryption();

public:
    DatabaseEngine();
    ~DatabaseEngine();

    bool open(const std::string& path, const std::string& key = "");
    void close();
    bool isOpen() const;

    DatabaseResult executeQuery(const std::string& query);
    DatabaseResult executePrepared(const std::string& query, const std::vector<std::string>& params);

    bool createTable(const DatabaseTable& table);
    bool createIndex(const std::string& indexName, const std::string& tableName, 
                    const std::vector<std::string>& columns);
    bool dropTable(const std::string& tableName);
    bool addColumn(const std::string& tableName, const DatabaseColumn& column);

    std::vector<std::string> getTableNames();
    std::vector<DatabaseColumn> getTableSchema(const std::string& tableName);

    QueryBuilder query();
    
    DatabaseResult select(const std::string& table, const std::vector<std::string>& columns = {"*"}, 
                         const std::string& where = "", const std::string& orderBy = "", 
                         int limit = -1, int offset = -1);
    DatabaseResult insert(const std::string& table, const std::unordered_map<std::string, std::string>& values, 
                         const std::string& conflictResolution = "");
    DatabaseResult update(const std::string& table, const std::unordered_map<std::string, std::string>& values, 
                         const std::string& where = "");
    DatabaseResult deleteRows(const std::string& table, const std::string& where = "");

    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();

    bool backupDatabase(const std::string& backupPath);
    bool vacuum();
    
    int getLastInsertRowId() const;
    int getTotalChanges() const;
    std::string getError() const;
    
    bool tableExists(const std::string& tableName);
    DatabaseResult rawQuery(const std::string& sql);
    bool executeScript(const std::string& sqlScript);

    void registerChangeCallback(std::function<void(const std::string&)> callback);
    void unregisterChangeCallbacks();

    DatabaseResult fullTextSearch(const std::string& table, const std::string& searchTerm, 
                                 const std::vector<std::string>& columns);
    
    bool enableWALMode();
    bool setSynchronousMode(const std::string& mode);
    bool setCacheSize(int size);
    
    bool migrateSchema(const std::vector<std::string>& migrationScripts);
    
    void executeAsync(std::function<void()> task);
    DatabaseResult paginatedQuery(const std::string& query, int page, int pageSize);
    
    bool createTrigger(const std::string& triggerName, const std::string& tableName,
                      const std::string& triggerTime, const std::string& triggerEvent,
                      const std::string& triggerBody);
    
    void registerCustomFunction(const std::string& name, int numArgs,
                               std::function<void(sqlite3_context*, int, sqlite3_value**)> func);
    
    bool optimizeDatabase();
    size_t getDatabaseSize();
    bool compactDatabase();
};

#endif