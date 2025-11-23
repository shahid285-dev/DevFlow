#include "database_engine.hpp"
#include <regex>
#include <set>
#include <stack>
#include <cctype>

class SQLSchemaParser : public DatabaseEngine {
private:
    struct SQLToken {
        std::string value;
        std::string type;
        int line;
        int position;
        
        SQLToken(const std::string& val, const std::string& typ, int ln, int pos) 
            : value(val), type(typ), line(ln), position(pos) {}
    };

    struct ParsedSchema {
        std::vector<DatabaseTable> tables;
        std::vector<std::pair<std::string, std::string>> indices;
        std::vector<std::string> triggers;
        std::vector<std::string> views;
        std::string schemaName;
        int version;
        std::string checksum;
    };

    struct SchemaValidationResult {
        bool isValid;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::unordered_map<std::string, std::vector<std::string>> tableDependencies;
    };

    std::vector<SQLToken> tokenizeSQL(const std::string& sql);
    DatabaseTable parseCreateTable(const std::vector<SQLToken>& tokens, size_t& index);
    DatabaseColumn parseColumnDefinition(const std::vector<SQLToken>& tokens, size_t& index);
    std::string parseTableConstraint(const std::vector<SQLToken>& tokens, size_t& index);
    void validateSchemaConsistency(const ParsedSchema& schema, SchemaValidationResult& result);
    void resolveTableDependencies(ParsedSchema& schema);
    std::string generateSchemaChecksum(const ParsedSchema& schema);
    bool validateDataType(const std::string& dataType);
    std::string extractTableNameFromDML(const std::string& sql);

public:
    SQLSchemaParser() : DatabaseEngine() {}
    
    ParsedSchema parseSQLFile(const std::string& filePath);
    ParsedSchema parseSQLString(const std::string& sqlContent);
    SchemaValidationResult validateSchema(const ParsedSchema& schema);
    bool executeSchema(const ParsedSchema& schema);
    bool executeSQLFile(const std::string& filePath);
    std::vector<std::string> extractTableNames(const ParsedSchema& schema);
    std::vector<std::string> extractColumnNames(const ParsedSchema& schema, const std::string& tableName);
    bool compareSchemas(const ParsedSchema& schema1, const ParsedSchema& schema2);
    ParsedSchema generateMigrationSchema(const ParsedSchema& fromSchema, const ParsedSchema& toSchema);
    bool executeMigration(const ParsedSchema& migrationSchema);
    std::unordered_map<std::string, std::string> getSchemaDifferences(const ParsedSchema& schema1, const ParsedSchema& schema2);
    bool verifySchemaIntegrity(const ParsedSchema& schema);
    std::vector<std::string> findOrphanedTables(const ParsedSchema& schema);
    bool optimizeSchema(const ParsedSchema& schema);
    std::string generateSchemaDocumentation(const ParsedSchema& schema);
    bool backupSchema(const ParsedSchema& schema, const std::string& backupPath);
    ParsedSchema loadSchemaFromBackup(const std::string& backupPath);
    bool validateSQLSyntax(const std::string& sql);
    std::vector<std::string> extractSQLStatements(const std::string& sqlContent);
    bool executeSchemaWithVerification(const ParsedSchema& schema);
    std::unordered_map<std::string, int> getSchemaStatistics(const ParsedSchema& schema);
};

std::vector<SQLSchemaParser::SQLToken> SQLSchemaParser::tokenizeSQL(const std::string& sql) {
    std::vector<SQLToken> tokens;
    std::string currentToken;
    bool inString = false;
    bool inComment = false;
    char stringDelimiter = '\0';
    int line = 1;
    int position = 1;
    int tokenStartPos = 1;

    auto addToken = [&](const std::string& type) {
        if (!currentToken.empty()) {
            tokens.emplace_back(currentToken, type, line, tokenStartPos);
            currentToken.clear();
        }
    };

    for (size_t i = 0; i < sql.length(); ++i) {
        char c = sql[i];
        
        if (c == '\n') {
            line++;
            position = 1;
            if (inComment) inComment = false;
            continue;
        }

        if (inComment) {
            position++;
            continue;
        }

        if (inString) {
            currentToken += c;
            if (c == stringDelimiter && sql[i-1] != '\\') {
                inString = false;
                addToken("STRING");
            }
            position++;
            continue;
        }

        if (c == '\'' || c == '"') {
            addToken("IDENTIFIER");
            inString = true;
            stringDelimiter = c;
            currentToken += c;
            tokenStartPos = position;
            position++;
            continue;
        }

        if (c == '-' && i + 1 < sql.length() && sql[i+1] == '-') {
            addToken("IDENTIFIER");
            inComment = true;
            i++;
            position += 2;
            continue;
        }

        if (std::isspace(c)) {
            addToken("IDENTIFIER");
            position++;
            continue;
        }

        if (std::isalnum(c) || c == '_' || c == '$') {
            if (currentToken.empty()) {
                tokenStartPos = position;
            }
            currentToken += c;
            position++;
            continue;
        }

        addToken("IDENTIFIER");

        std::string punct(1, c);
        tokens.emplace_back(punct, "PUNCTUATION", line, position);
        position++;
    }

    addToken("IDENTIFIER");

    for (auto& token : tokens) {
        std::string upperToken = token.value;
        std::transform(upperToken.begin(), upperToken.end(), upperToken.begin(), ::toupper);
        
        static const std::set<std::string> keywords = {
            "CREATE", "TABLE", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
            "ALTER", "INDEX", "VIEW", "TRIGGER", "PRIMARY", "KEY", "FOREIGN",
            "REFERENCES", "UNIQUE", "NOT", "NULL", "DEFAULT", "AUTOINCREMENT",
            "CHECK", "CONSTRAINT", "INTEGER", "TEXT", "REAL", "BLOB", "NUMERIC",
            "BOOLEAN", "DATE", "DATETIME", "IF", "EXISTS", "OR", "REPLACE",
            "TEMPORARY", "TEMPORARY", "AS", "FROM", "WHERE", "ORDER", "BY",
            "GROUP", "HAVING", "LIMIT", "OFFSET", "JOIN", "INNER", "LEFT",
            "RIGHT", "OUTER", "ON", "AND", "OR", "IN", "BETWEEN", "LIKE",
            "IS", "VALUES", "SET", "INTO", "BEGIN", "COMMIT", "ROLLBACK",
            "TRANSACTION", "WITH", "RECURSIVE", "CASE", "WHEN", "THEN", "ELSE",
            "END", "DISTINCT", "UNION", "ALL", "EXCEPT", "INTERSECT", "ASC",
            "DESC", "COLLATE", "NOCASE", "RTRIM", "GLOB", "REGEXP", "MATCH",
            "ESCAPE", "CAST", "VACUUM", "ANALYZE", "PRAGMA", "ATTACH", "DETACH",
            "DATABASE", "USING", "INDEXED", "NOTINDEXED", "PLAN", "EXPLAIN",
            "ABORT", "FAIL", "IGNORE", "REPLACE", "CONFLICT", "RAISE", "APPLICATION",
            "ID", "CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP"
        };

        if (keywords.find(upperToken) != keywords.end()) {
            token.type = "KEYWORD";
        } else if (std::regex_match(token.value, std::regex(R"(^-?\d+\.?\d*$)"))) {
            token.type = "NUMBER";
        }
    }

    return tokens;
}

SQLSchemaParser::ParsedSchema SQLSchemaParser::parseSQLFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open SQL file: " + filePath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parseSQLString(buffer.str());
}

SQLSchemaParser::ParsedSchema SQLSchemaParser::parseSQLString(const std::string& sqlContent) {
    ParsedSchema schema;
    schema.version = 1;
    
    auto tokens = tokenizeSQL(sqlContent);
    size_t index = 0;

    while (index < tokens.size()) {
        if (tokens[index].type == "KEYWORD") {
            std::string keyword = tokens[index].value;
            std::transform(keyword.begin(), keyword.end(), keyword.begin(), ::toupper);

            if (keyword == "CREATE") {
                if (index + 1 < tokens.size()) {
                    std::string objectType = tokens[index + 1].value;
                    std::transform(objectType.begin(), objectType.end(), objectType.begin(), ::toupper);

                    if (objectType == "TABLE") {
                        schema.tables.push_back(parseCreateTable(tokens, index));
                    } else if (objectType == "INDEX") {
                        std::string indexName, tableName;
                        index += 2;
                        
                        if (index < tokens.size() && tokens[index].type == "IDENTIFIER") {
                            indexName = tokens[index].value;
                            index++;
                        }
                        
                        if (index < tokens.size() && tokens[index].value == "ON") {
                            index++;
                            if (index < tokens.size() && tokens[index].type == "IDENTIFIER") {
                                tableName = tokens[index].value;
                                schema.indices.emplace_back(indexName, tableName);
                            }
                        }
                    } else if (objectType == "TRIGGER") {
                        std::string triggerSql;
                        while (index < tokens.size() && tokens[index].value != ";") {
                            triggerSql += tokens[index].value + " ";
                            index++;
                        }
                        schema.triggers.push_back(triggerSql);
                    } else if (objectType == "VIEW") {
                        std::string viewSql;
                        while (index < tokens.size() && tokens[index].value != ";") {
                            viewSql += tokens[index].value + " ";
                            index++;
                        }
                        schema.views.push_back(viewSql);
                    }
                }
            }
        }
        index++;
    }

    schema.checksum = generateSchemaChecksum(schema);
    resolveTableDependencies(schema);
    return schema;
}

DatabaseTable SQLSchemaParser::parseCreateTable(const std::vector<SQLToken>& tokens, size_t& index) {
    DatabaseTable table;
    
    index += 2;
    if (index >= tokens.size() || tokens[index].type != "IDENTIFIER") {
        throw std::runtime_error("Expected table name after CREATE TABLE");
    }
    
    table.name = tokens[index].value;
    index++;
    
    if (index >= tokens.size() || tokens[index].value != "(") {
        throw std::runtime_error("Expected '(' after table name");
    }
    index++;
    
    bool parsingColumns = true;
    while (index < tokens.size() && tokens[index].value != ")") {
        if (tokens[index].value == ",") {
            index++;
            continue;
        }
        
        if (tokens[index].type == "IDENTIFIER") {
            table.columns.push_back(parseColumnDefinition(tokens, index));
        } else if (tokens[index].type == "KEYWORD") {
            std::string constraint = parseTableConstraint(tokens, index);
        } else {
            index++;
        }
    }
    
    if (index < tokens.size() && tokens[index].value == ")") {
        index++;
    }
    
    return table;
}

DatabaseColumn SQLSchemaParser::parseColumnDefinition(const std::vector<SQLToken>& tokens, size_t& index) {
    if (index >= tokens.size() || tokens[index].type != "IDENTIFIER") {
        throw std::runtime_error("Expected column name");
    }
    
    std::string columnName = tokens[index].value;
    index++;
    
    if (index >= tokens.size() || tokens[index].type != "IDENTIFIER") {
        throw std::runtime_error("Expected data type for column " + columnName);
    }
    
    std::string dataType = tokens[index].value;
    if (!validateDataType(dataType)) {
        throw std::runtime_error("Invalid data type: " + dataType);
    }
    
    DatabaseColumn column(columnName, dataType);
    index++;
    
    while (index < tokens.size() && tokens[index].value != "," && tokens[index].value != ")") {
        std::string keyword = tokens[index].value;
        std::transform(keyword.begin(), keyword.end(), keyword.begin(), ::toupper);
        
        if (keyword == "PRIMARY") {
            if (index + 1 < tokens.size() && tokens[index + 1].value == "KEY") {
                column.primaryKey = true;
                index += 2;
                
                if (index < tokens.size() && tokens[index].value == "AUTOINCREMENT") {
                    column.autoIncrement = true;
                    index++;
                }
            }
        } else if (keyword == "NOT") {
            if (index + 1 < tokens.size() && tokens[index + 1].value == "NULL") {
                column.notNull = true;
                index += 2;
            }
        } else if (keyword == "DEFAULT") {
            if (index + 1 < tokens.size()) {
                column.defaultValue = tokens[index + 1].value;
                index += 2;
            }
        } else if (keyword == "UNIQUE") {
            column.indexed = true;
            index++;
        } else {
            index++;
        }
    }
    
    return column;
}

std::string SQLSchemaParser::parseTableConstraint(const std::vector<SQLToken>& tokens, size_t& index) {
    std::string constraint;
    while (index < tokens.size() && tokens[index].value != "," && tokens[index].value != ")") {
        constraint += tokens[index].value + " ";
        index++;
    }
    return constraint;
}

SQLSchemaParser::SchemaValidationResult SQLSchemaParser::validateSchema(const ParsedSchema& schema) {
    SchemaValidationResult result;
    result.isValid = true;
    
    validateSchemaConsistency(schema, result);
    
    std::set<std::string> tableNames;
    for (const auto& table : schema.tables) {
        if (tableNames.find(table.name) != tableNames.end()) {
            result.errors.push_back("Duplicate table name: " + table.name);
            result.isValid = false;
        }
        tableNames.insert(table.name);
        
        std::set<std::string> columnNames;
        for (const auto& column : table.columns) {
            if (columnNames.find(column.name) != columnNames.end()) {
                result.errors.push_back("Duplicate column name: " + column.name + " in table: " + table.name);
                result.isValid = false;
            }
            columnNames.insert(column.name);
            
            if (!validateDataType(column.type)) {
                result.errors.push_back("Invalid data type: " + column.type + " for column: " + column.name);
                result.isValid = false;
            }
        }
    }
    
    for (const auto& index : schema.indices) {
        if (tableNames.find(index.second) == tableNames.end()) {
            result.warnings.push_back("Index references non-existent table: " + index.second);
        }
    }
    
    return result;
}

bool SQLSchemaParser::executeSchema(const ParsedSchema& schema) {
    if (!beginTransaction()) {
        return false;
    }
    
    try {
        for (const auto& table : schema.tables) {
            if (!createTable(table)) {
                rollbackTransaction();
                return false;
            }
        }
        
        for (const auto& index : schema.indices) {
            std::string createIndexSQL = "CREATE INDEX IF NOT EXISTS " + index.first + " ON " + index.second;
            DatabaseResult result = executeQuery(createIndexSQL);
            if (!result.success) {
                rollbackTransaction();
                return false;
            }
        }
        
        for (const auto& trigger : schema.triggers) {
            DatabaseResult result = executeQuery(trigger);
            if (!result.success) {
                rollbackTransaction();
                return false;
            }
        }
        
        for (const auto& view : schema.views) {
            DatabaseResult result = executeQuery(view);
            if (!result.success) {
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

bool SQLSchemaParser::executeSQLFile(const std::string& filePath) {
    try {
        ParsedSchema schema = parseSQLFile(filePath);
        SchemaValidationResult validation = validateSchema(schema);
        
        if (!validation.isValid) {
            for (const auto& error : validation.errors) {
                logError("schema_validation", error, 4001);
            }
            return false;
        }
        
        return executeSchema(schema);
    } catch (const std::exception& e) {
        logError("execute_sql_file", "Failed to execute SQL file", 4002, {{"error", e.what()}});
        return false;
    }
}

std::vector<std::string> SQLSchemaParser::extractTableNames(const ParsedSchema& schema) {
    std::vector<std::string> tableNames;
    for (const auto& table : schema.tables) {
        tableNames.push_back(table.name);
    }
    return tableNames;
}

std::vector<std::string> SQLSchemaParser::extractColumnNames(const ParsedSchema& schema, const std::string& tableName) {
    std::vector<std::string> columnNames;
    for (const auto& table : schema.tables) {
        if (table.name == tableName) {
            for (const auto& column : table.columns) {
                columnNames.push_back(column.name);
            }
            break;
        }
    }
    return columnNames;
}

bool SQLSchemaParser::compareSchemas(const ParsedSchema& schema1, const ParsedSchema& schema2) {
    return schema1.checksum == schema2.checksum;
}

SQLSchemaParser::ParsedSchema SQLSchemaParser::generateMigrationSchema(const ParsedSchema& fromSchema, const ParsedSchema& toSchema) {
    ParsedSchema migrationSchema;
    migrationSchema.version = toSchema.version;
    
    std::set<std::string> fromTables, toTables;
    for (const auto& table : fromSchema.tables) fromTables.insert(table.name);
    for (const auto& table : toSchema.tables) toTables.insert(table.name);
    
    for (const auto& table : toSchema.tables) {
        if (fromTables.find(table.name) == fromTables.end()) {
            migrationSchema.tables.push_back(table);
        }
    }
    
    for (const auto& table : fromSchema.tables) {
        if (toTables.find(table.name) == toTables.end()) {
            std::string dropTableSQL = "DROP TABLE IF EXISTS " + table.name;
            migrationSchema.triggers.push_back(dropTableSQL);
        }
    }
    
    migrationSchema.checksum = generateSchemaChecksum(migrationSchema);
    return migrationSchema;
}

bool SQLSchemaParser::executeMigration(const ParsedSchema& migrationSchema) {
    return executeSchema(migrationSchema);
}

std::unordered_map<std::string, std::string> SQLSchemaParser::getSchemaDifferences(const ParsedSchema& schema1, const ParsedSchema& schema2) {
    std::unordered_map<std::string, std::string> differences;
    
    if (schema1.checksum != schema2.checksum) {
        differences["checksum"] = "Schemas have different checksums";
    }
    
    if (schema1.tables.size() != schema2.tables.size()) {
        differences["table_count"] = "Different number of tables";
    }
    
    return differences;
}

bool SQLSchemaParser::verifySchemaIntegrity(const ParsedSchema& schema) {
    for (const auto& table : schema.tables) {
        if (!tableExists(table.name)) {
            return false;
        }
        
        auto existingColumns = getTableSchema(table.name);
        if (existingColumns.size() != table.columns.size()) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> SQLSchemaParser::findOrphanedTables(const ParsedSchema& schema) {
    std::vector<std::string> orphanedTables;
    auto allTables = getTableNames();
    std::set<std::string> schemaTables;
    
    for (const auto& table : schema.tables) {
        schemaTables.insert(table.name);
    }
    
    for (const auto& table : allTables) {
        if (schemaTables.find(table) == schemaTables.end()) {
            orphanedTables.push_back(table);
        }
    }
    
    return orphanedTables;
}

bool SQLSchemaParser::optimizeSchema(const ParsedSchema& schema) {
    bool success = true;
    
    for (const auto& table : schema.tables) {
        for (const auto& column : table.columns) {
            if (column.indexed && !column.primaryKey) {
                std::string indexName = table.name + "_" + column.name + "_idx";
                success &= createIndex(indexName, table.name, {column.name});
            }
        }
    }
    
    success &= vacuum();
    success &= optimizeDatabase();
    
    return success;
}

std::string SQLSchemaParser::generateSchemaDocumentation(const ParsedSchema& schema) {
    std::stringstream docs;
    docs << "Schema Documentation\n";
    docs << "===================\n\n";
    docs << "Schema Name: " << schema.schemaName << "\n";
    docs << "Version: " << schema.version << "\n";
    docs << "Checksum: " << schema.checksum << "\n\n";
    
    docs << "Tables:\n";
    docs << "-------\n";
    for (const auto& table : schema.tables) {
        docs << "Table: " << table.name << "\n";
        docs << "Columns:\n";
        for (const auto& column : table.columns) {
            docs << "  - " << column.name << " (" << column.type << ")";
            if (column.primaryKey) docs << " PRIMARY KEY";
            if (column.autoIncrement) docs << " AUTOINCREMENT";
            if (column.notNull) docs << " NOT NULL";
            if (!column.defaultValue.empty()) docs << " DEFAULT " << column.defaultValue;
            docs << "\n";
        }
        docs << "\n";
    }
    
    return docs.str();
}

bool SQLSchemaParser::backupSchema(const ParsedSchema& schema, const std::string& backupPath) {
    std::ofstream backupFile(backupPath);
    if (!backupFile.is_open()) {
        return false;
    }
    
    backupFile << generateSchemaDocumentation(schema);
    backupFile.close();
    return true;
}

SQLSchemaParser::ParsedSchema SQLSchemaParser::loadSchemaFromBackup(const std::string& backupPath) {
    return parseSQLFile(backupPath);
}

bool SQLSchemaParser::validateSQLSyntax(const std::string& sql) {
    try {
        auto tokens = tokenizeSQL(sql);
        return !tokens.empty();
    } catch (...) {
        return false;
    }
}

std::vector<std::string> SQLSchemaParser::extractSQLStatements(const std::string& sqlContent) {
    std::vector<std::string> statements;
    std::string currentStatement;
    bool inString = false;
    char stringDelimiter = '\0';
    
    for (char c : sqlContent) {
        if (c == '\'' || c == '"') {
            if (!inString) {
                inString = true;
                stringDelimiter = c;
            } else if (c == stringDelimiter) {
                inString = false;
            }
        }
        
        currentStatement += c;
        
        if (c == ';' && !inString) {
            statements.push_back(currentStatement);
            currentStatement.clear();
        }
    }
    
    if (!currentStatement.empty()) {
        statements.push_back(currentStatement);
    }
    
    return statements;
}

bool SQLSchemaParser::executeSchemaWithVerification(const ParsedSchema& schema) {
    if (!executeSchema(schema)) {
        return false;
    }
    
    return verifySchemaIntegrity(schema);
}

std::unordered_map<std::string, int> SQLSchemaParser::getSchemaStatistics(const ParsedSchema& schema) {
    std::unordered_map<std::string, int> stats;
    stats["tables"] = schema.tables.size();
    stats["indices"] = schema.indices.size();
    stats["triggers"] = schema.triggers.size();
    stats["views"] = schema.views.size();
    
    int totalColumns = 0;
    int primaryKeys = 0;
    int indexedColumns = 0;
    
    for (const auto& table : schema.tables) {
        totalColumns += table.columns.size();
        for (const auto& column : table.columns) {
            if (column.primaryKey) primaryKeys++;
            if (column.indexed) indexedColumns++;
        }
    }
    
    stats["columns"] = totalColumns;
    stats["primary_keys"] = primaryKeys;
    stats["indexed_columns"] = indexedColumns;
    
    return stats;
}

void SQLSchemaParser::validateSchemaConsistency(const ParsedSchema& schema, SchemaValidationResult& result) {
    std::set<std::string> tableNames;
    for (const auto& table : schema.tables) {
        tableNames.insert(table.name);
    }
    
    for (const auto& table : schema.tables) {
        for (const auto& column : table.columns) {
            if (column.primaryKey && column.autoIncrement && column.type != "INTEGER") {
                result.warnings.push_back("Autoincrement should be used with INTEGER type in table: " + table.name);
            }
        }
    }
}

void SQLSchemaParser::resolveTableDependencies(ParsedSchema& schema) {
    std::vector<DatabaseTable> orderedTables;
    std::set<std::string> processedTables;
    
    while (orderedTables.size() < schema.tables.size()) {
        bool progress = false;
        
        for (const auto& table : schema.tables) {
            if (processedTables.find(table.name) != processedTables.end()) {
                continue;
            }
            
            bool canProcess = true;
            for (const auto& column : table.columns) {
            }
            
            if (canProcess) {
                orderedTables.push_back(table);
                processedTables.insert(table.name);
                progress = true;
            }
        }
        
        if (!progress) {
            break;
        }
    }
    
    schema.tables = orderedTables;
}

std::string SQLSchemaParser::generateSchemaChecksum(const ParsedSchema& schema) {
    std::stringstream ss;
    ss << schema.version << schema.schemaName;
    
    for (const auto& table : schema.tables) {
        ss << table.name;
        for (const auto& column : table.columns) {
            ss << column.name << column.type << column.primaryKey << column.autoIncrement;
        }
    }
    
    std::hash<std::string> hasher;
    return std::to_string(hasher(ss.str()));
}

bool SQLSchemaParser::validateDataType(const std::string& dataType) {
    static const std::set<std::string> validTypes = {
        "INTEGER", "TEXT", "REAL", "BLOB", "NUMERIC",
        "BOOLEAN", "DATE", "DATETIME", "VARCHAR", "CHAR",
        "FLOAT", "DOUBLE", "DECIMAL", "BIGINT", "SMALLINT", "TINYINT"
    };
    
    std::string upperType = dataType;
    std::transform(upperType.begin(), upperType.end(), upperType.begin(), ::toupper);
    
    return validTypes.find(upperType) != validTypes.end();
}

std::string SQLSchemaParser::extractTableNameFromDML(const std::string& sql) {
    auto tokens = tokenizeSQL(sql);
    
    for (size_t i = 0; i < tokens.size(); ++i) {
        std::string keyword = tokens[i].value;
        std::transform(keyword.begin(), keyword.end(), keyword.begin(), ::toupper);
        
        if ((keyword == "INSERT" || keyword == "UPDATE" || keyword == "DELETE") &&
            i + 1 < tokens.size()) {
            
            if (tokens[i + 1].value == "INTO") {
                if (i + 2 < tokens.size()) {
                    return tokens[i + 2].value;
                }
            } else {
                return tokens[i + 1].value;
            }
        }
    }
    
    return "";
}



