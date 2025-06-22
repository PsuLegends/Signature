#!/bin/bash

# Путь к исполняемому файлу клиента
CLIENT_EXECUTABLE="./client"

# IP и порт сервера
SERVER_IP="127.0.0.1"
PORT="33333"

# Общие параметры
OPERATION="1"
USERNAME="new"
PASSWORD="new"

# Количество клиентов
NUM_CLIENTS=4

for ((i=1; i<=NUM_CLIENTS; i++)); do
    echo "[INFO] Запуск клиента #$i в новом окне konsole"
    konsole --new-tab -p tabtitle="Client #$i" -e bash -c "$CLIENT_EXECUTABLE -s $SERVER_IP -p $PORT --operation $OPERATION --username $USERNAME --password $PASSWORD; exec bash" &
    sleep 3
done
