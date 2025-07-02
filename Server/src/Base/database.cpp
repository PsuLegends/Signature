#include "database.h"

base::base()
{
    if (!connectToDatabase("client_base.db"))
    {
        qCritical() << "Не удалось подключиться к базе данных.";
    }
}
bool base::connectToDatabase(const std::string &dbName)
{
    QFileInfo dbFile(QString::fromStdString(dbName));
    if (!dbFile.exists() || !dbFile.isFile())
    {
        qCritical() << "Ошибка: файл базы данных не найден:" << QString::fromStdString(dbName);
        exit(1);
        return false;
    }
    db.setDatabaseName(QString::fromStdString(dbName));
    if (!db.open())
    {
        printQueryError(query, "CONNECT");
        return false;
    }
    qDebug() << "Подключение к базе данных успешно.";
    return true;
}
bool base::insertUser(const std::string &username, const std::string &password, const std::string &ip)
{
    query.prepare("INSERT INTO users (username, password, ip) VALUES (:username, :password, :ip)");
    query.bindValue(":username", QString::fromStdString(username));
    query.bindValue(":password", QString::fromStdString(password));
    query.bindValue(":ip", QString::fromStdString(ip));
    if (!query.exec())
    {
        printQueryError(query, "INSERT");
        return false;
    }
    qDebug() << "Пользователь успешно добавлен.";
    return true;
}
bool base::selectUserByName(std::string name)
{
    query.prepare("SELECT * FROM users WHERE username = :name");
    query.bindValue(":name", QString::fromStdString(name));
    if (!query.exec())
    {
        printQueryError(query, "SELECT");
        return false;
    }
    if (query.next())
    {
        int userId = query.value(0).toInt();
        QString username = query.value(1).toString();
        QString password = query.value(2).toString();
        QString ip = query.value(3).toString();
        current_ip_ = ip.toStdString();
        current_hashed_password_ = password.toStdString();
        qDebug() << "ID: " << userId << "Username: " << username << "Password: " << password << "IP: " << ip;
        return true;
    }
    else
    {
        qDebug() << "Пользователь не найден.";
        return false;
    }
}

std::string base::getCurrentIP() const
{
    return current_ip_;
}
std::string base::getCurrentHashedPassword() const
{
    return current_hashed_password_;
}

void base::printQueryError(const QSqlQuery &query, const std::string &queryType)
{
    qCritical() << "Ошибка SQL-запроса типа:" << QString::fromStdString(queryType)
                << "с сообщением:" << query.lastError().text();
}
