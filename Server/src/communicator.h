#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <memory>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <atomic>
#include <random>
#include <chrono>
#include <thread>
#include <limits>
#include "logger.h"
#include "error.h"
#include "data_handler.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include "base.h"
#include "protocol.h"
#include "rsa_crypto.h"
class communicator
{
private:
    const size_t keyLength = 2048;
    base db;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addr_size;
    std::string base_location;
    size_t buflen = 65536;
    std::unique_ptr<char[]> buffer{new char[buflen]};
    uint p;
    std::string digits[16] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};

public:
    int serverSocket;
    logger log;
    std::string cl_id, log_location;
    timeval timeout{};
    std::atomic<int> active_clients{0};
    communicator(uint port, std::string log_loc);

    int connect_to_cl(int &new_socket, sockaddr_in &out_clientAddr);
    int send_data(int client_socket, const std::string &header, const std::string &client_id, int message_id, const std::string &msg);
    std::string recv_data(int client_socket, std::string messg);
    void close_sock(int sock);
    void work();
    void start();
    int send_file_list(int client_socket);
    int send_file(int client_socket, std::string &file_path);
    int file_exchange(int client_socket);
    int authentification(int client_socket, std::string cl_id);
    int registration(int client_socket, std::string cl_id);
    void handle_client(int client_socket, sockaddr_in clientAddr);
    void do_operation(std::string op);
    std::string hash_gen(std::string &password);
};
