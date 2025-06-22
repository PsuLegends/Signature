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
#include <random>
#include <chrono>
#include <algorithm>
#include <thread>
#include <limits>
#include "show_error.h"
#include "ui.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h> 
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iomanip>
#include "protocol.h"
class client {
    private:
        show_error debugger;
        timeval timeout{};
        std::string hash;
        std::string password;
        std::string id;
        std::string ip;
        struct sockaddr_in serverAddr;
        socklen_t addr_size;
        int buflen = 65600;
        std::unique_ptr<char[]> buffer{new char[buflen]};
        uint port;
        uint op;
        std::ifstream u_data;
        std::string hash_gen(std::string password);
        std::string hash_gen_file(std::string password);
    public:
        const char* serv_ip;
        int sock;
        std::vector <std::string> files;
        void connect_to_server();
        void send_data(const std::string& header, const std::string& client_id, int message_id, const std::string& msg);
        std::string recv_data(std::string error_msg);
        void close_sock();
        void start();
        void work(UI &intf);
        void client_auth();
        void client_reg();
        std::vector<std::string> recv_vector();
        void print_vector(const std::vector<std::string>& vec);
        int recv_file(std::string& file_path);
};