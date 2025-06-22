#include "base.h"

base::base() {
    // Попытка подключения к базе данных "client_base.db" при создании объекта.
    if (!connectToDatabase("client_base.db")) {
        // Если подключение не удалось, выводим критическую ошибку в журнал
        qCritical() << "Не удалось подключиться к базе данных.";
    }
}

// Подключение к базе данных
bool base::connectToDatabase(const std::string& dbName) {
    // Проверяем существование файла базы данных
    QFileInfo dbFile(QString::fromStdString(dbName));
    if (!dbFile.exists() || !dbFile.isFile()) {
        qCritical() << "Ошибка: файл базы данных не найден:" << QString::fromStdString(dbName);
        exit(1);
        return false;
    }

    // Устанавливаем имя базы данных для объекта db
    db.setDatabaseName(QString::fromStdString(dbName));
    
    // Пытаемся открыть соединение с базой данных
    if (!db.open()) {
        // Если не удалось подключиться, выводим ошибку и возвращаем false
        printQueryError(query, "CONNECT");
        return false;
    }
    
    // Если подключение успешно, выводим сообщение
    qDebug() << "Подключение к базе данных успешно.";
    return true;
}


// Функция для вставки нового пользователя в таблицу
bool base::insertUser(const std::string& username, const std::string& password, const std::string& ip) {
    // Подготавливаем SQL-запрос для вставки данных пользователя в таблицу "users"
    query.prepare("INSERT INTO users (username, password, ip) VALUES (:username, :password, :ip)");
    
    // Привязываем значения параметров к запросу
    query.bindValue(":username", QString::fromStdString(username));
    query.bindValue(":password", QString::fromStdString(password));
    query.bindValue(":ip", QString::fromStdString(ip));

    // Выполняем запрос на выполнение
    if (!query.exec()) {
        // Если запрос не выполнен, выводим ошибку и возвращаем false
        printQueryError(query, "INSERT");
        return false;
    }
    
    // Если запрос успешен, выводим сообщение о добавлении пользователя
    qDebug() << "Пользователь успешно добавлен.";
    return true;
}
// Функция для выбора пользователя по имени
bool base::selectUserByName(std::string name) {
    // Подготавливаем SQL-запрос для выбора пользователя по имени
    query.prepare("SELECT * FROM users WHERE username = :name");
    query.bindValue(":name", QString::fromStdString(name));

    // Выполняем запрос
    if (!query.exec()) {
        // Если запрос не выполнен, выводим ошибку и возвращаем false
        printQueryError(query, "SELECT");
        return false;
    }

    // Если пользователь найден, извлекаем его данные
    if (query.next()) {
        int userId = query.value(0).toInt();       // Извлекаем ID пользователя
        QString username = query.value(1).toString();  // Извлекаем имя пользователя
        QString password = query.value(2).toString();  // Извлекаем пароль пользователя
        QString ip = query.value(3).toString();      // Извлекаем IP пользователя

        // Сохраняем текущие значения
        current_ip_ = ip.toStdString();
        current_hashed_password_ = password.toStdString();

        // Логируем информацию о пользователе
        qDebug() << "ID: " << userId << "Username: " << username << "Password: " << password << "IP: " << ip;
        return true;
    } else {
        // Если пользователь не найден, выводим соответствующее сообщение
        qDebug() << "Пользователь не найден.";
        return false;
    }
}
// Функция для получения текущего IP
std::string base::getCurrentIP() const {
    return current_ip_;  // Возвращает текущий IP пользователя
}

// Функция для получения текущего хешированного пароля
std::string base::getCurrentHashedPassword() const {
    return current_hashed_password_;  // Возвращает текущий хешированный пароль пользователя
}

// Функция для вывода ошибки SQL-запроса
void base::printQueryError(const QSqlQuery& query, const std::string& queryType) {
    // Выводит сообщение об ошибке, связанной с выполнением SQL-запроса
    qCritical() << "Ошибка SQL-запроса типа:" << QString::fromStdString(queryType)
                << "с сообщением:" << query.lastError().text();
}
