#pragma once
#include <string>
#include <vector>
#include <memory>
#include "../Logger/logger.h"
#include <filesystem>
#include <QCoreApplication>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <QFileInfo>
#include <QString>
#include <QDebug>
class base {
private:
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    QSqlQuery query;

public:
    base();
    bool connectToDatabase(const std::string& dbName);
    bool insertUser(const std::string& username, const std::string& password, const std::string& ip);
    bool selectUserByName(std::string name);
    void printQueryError(const QSqlQuery& query, const std::string& queryType);
    std::string current_ip_;
    std::string current_hashed_password_;
    std::string getCurrentIP() const;
    std::string getCurrentHashedPassword() const;
};
