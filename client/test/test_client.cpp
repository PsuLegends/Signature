#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <optional>
#include <cstring>
#include <limits>
#include <iomanip> // Для std::hex, std::setw, std::setfill
#include <algorithm> // для std::min

// Системные заголовочные файлы
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

// --- Флаг отладки ---
const bool DEBUG_MODE = true;

// --- Утилиты для отладки ---
void print_hex_dump(const std::string& prefix, const std::string& data) {
    if (!DEBUG_MODE) return;
    std::cout << "\n================================\n"
              << "[DEBUG] " << prefix << " (" << data.size() << " bytes):\n"
              << "[HEX]   | ";
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    std::cout << std::dec << "\n[ASCII] | '";
    for (char c : data) {
        if (isprint(c)) std::cout << c;
        else std::cout << '.';
    }
    std::cout << "'\n================================\n" << std::endl;
}


// --- Встроенная реализация SHA-256 ---
namespace {
    class SHA256 {
    protected:
        typedef unsigned char uint8; typedef unsigned int uint32; typedef unsigned long long uint64;
        const static uint32 sha256_k[]; static const unsigned int SHA224_256_BLOCK_SIZE = (512 / 8);
    public:
        void init(); void update(const unsigned char *message, unsigned int len); void final(unsigned char *digest); static const unsigned int DIGEST_SIZE = (256 / 8);
    protected:
        void transform(const unsigned char *message, unsigned int block_nb); unsigned int m_tot_len; unsigned int m_len; unsigned char m_block[2 * SHA224_256_BLOCK_SIZE]; uint32 m_h[8];
    };
    #define SHA2_SHFR(x, n)    (x >> n)
    #define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
    #define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
    #define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
    #define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
    #define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
    #define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
    #define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
    #define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
    #define SHA2_UNPACK32(x, str) { *((str) + 3) = (uint8) ((x)); *((str) + 2) = (uint8) ((x) >>  8); *((str) + 1) = (uint8) ((x) >> 16); *((str) + 0) = (uint8) ((x) >> 24); }
    #define SHA2_PACK32(str, x)   { *(x) =   ((uint32) *((str) + 3)) | ((uint32) *((str) + 2) <<  8) | ((uint32) *((str) + 1) << 16) | ((uint32) *((str) + 0) << 24); }
    const unsigned int SHA256::sha256_k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    void SHA256::transform(const unsigned char *message, unsigned int block_nb){uint32 w[64];uint32 wv[8];uint32 t1, t2;const unsigned char *sub_block;int i;int j;for (i = 0; i < (int) block_nb; i++){sub_block = message + (i << 6);for (j = 0; j < 16; j++){SHA2_PACK32(&sub_block[j << 2], &w[j]);}for (j = 16; j < 64; j++){w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];}for (j = 0; j < 8; j++){wv[j] = m_h[j];}for (j = 0; j < 64; j++){t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);wv[7] = wv[6];wv[6] = wv[5];wv[5] = wv[4];wv[4] = wv[3] + t1;wv[3] = wv[2];wv[2] = wv[1];wv[1] = wv[0];wv[0] = t1 + t2;}for (j = 0; j < 8; j++){m_h[j] += wv[j];}}}
    void SHA256::init(){m_h[0] = 0x6a09e667;m_h[1] = 0xbb67ae85;m_h[2] = 0x3c6ef372;m_h[3] = 0xa54ff53a;m_h[4] = 0x510e527f;m_h[5] = 0x9b05688c;m_h[6] = 0x1f83d9ab;m_h[7] = 0x5be0cd19;m_len = 0;m_tot_len = 0;}
    void SHA256::update(const unsigned char *message, unsigned int len){unsigned int block_nb;unsigned int new_len, rem_len, tmp_len;const unsigned char *shifted_message;tmp_len = SHA224_256_BLOCK_SIZE - m_len;rem_len = len < tmp_len ? len : tmp_len;memcpy(&m_block[m_len], message, rem_len);if (m_len + len < SHA224_256_BLOCK_SIZE){m_len += len;return;}new_len = len - rem_len;block_nb = new_len / SHA224_256_BLOCK_SIZE;shifted_message = message + rem_len;transform(m_block, 1);transform(shifted_message, block_nb);rem_len = new_len % SHA224_256_BLOCK_SIZE;memcpy(m_block, &shifted_message[block_nb << 6], rem_len);m_len = rem_len;m_tot_len += (block_nb + 1) << 6;}
    void SHA256::final(unsigned char *digest){unsigned int block_nb;unsigned int pm_len;unsigned int len_b;int i;block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));len_b = (m_tot_len + m_len) << 3;pm_len = block_nb << 6;memset(m_block + m_len, 0, pm_len - m_len);m_block[m_len] = 0x80;SHA2_UNPACK32(len_b, m_block + pm_len - 4);transform(m_block, block_nb);for (i = 0 ; i < 8; i++){SHA2_UNPACK32(m_h[i], &digest[i << 2]);}}
    std::string sha256(const std::string& input){unsigned char digest[SHA256::DIGEST_SIZE];memset(digest,0,SHA256::DIGEST_SIZE);SHA256 ctx;ctx.init();ctx.update((unsigned char*)input.c_str(), input.length());ctx.final(digest);char buf[2*SHA256::DIGEST_SIZE+1];for(size_t i=0;i<SHA256::DIGEST_SIZE; i++){sprintf(buf+i*2, "%02x", digest[i]);}for(int i=0;buf[i];++i) buf[i] = toupper(buf[i]);return std::string(buf);}
}

namespace ClientProtocol {
    struct ParsedMessage { std::string header, clientID, message; int messageID = -1; };
    std::string build(const std::string& h,const std::string& c, int m,const std::string& b) { return h+"|clientID:"+c+"|messageID:"+std::to_string(m)+"|message:"+b+"\n"; }
    ParsedMessage parse(const std::string& raw) {
        ParsedMessage r; if(raw.empty()) return r;
        size_t p=0, n=raw.find('|'); if(n==std::string::npos){ r.header=raw; if(!r.header.empty()&&r.header.back()=='\n')r.header.pop_back(); return r; }
        r.header=raw.substr(0,n); p=n+1;
        while((n=raw.find('|', p)) != std::string::npos) {
            std::string part=raw.substr(p,n-p);
            if(part.rfind("clientID:",0)==0) r.clientID=part.substr(9);
            else if(part.rfind("messageID:",0)==0){try{r.messageID=std::stoi(part.substr(10));}catch(...){r.messageID=-1;}}
            p=n+1;
        }
        std::string last=raw.substr(p); if(last.rfind("message:",0)==0){r.message=last.substr(8);if(!r.message.empty()&&r.message.back()=='\n')r.message.pop_back();}
        return r;
    }
}

class Client {
private:
    std::string host;
    uint16_t port;
    int sockfd = -1;
    std::string recv_buffer; // Буфер для хранения "остатка" от предыдущего recv()

    void send_packet(const std::string& data) {
        print_hex_dump("SENDING PACKET", data);
        ssize_t total_sent = 0, to_send = data.size();
        while(total_sent < to_send){
            ssize_t sent = send(sockfd, data.c_str() + total_sent, to_send - total_sent, MSG_NOSIGNAL);
            if(sent <= 0) throw std::runtime_error("send() failed or connection closed.");
            total_sent += sent;
        }
    }
    
    // Новая, более простая и надежная логика получения данных
    std::string receive_data(size_t bytes_to_read) {
        // Сначала проверяем, нет ли уже нужных данных в нашем буфере
        if (recv_buffer.length() >= bytes_to_read) {
            std::string result = recv_buffer.substr(0, bytes_to_read);
            recv_buffer.erase(0, bytes_to_read);
            print_hex_dump("DATA (FROM BUFFER)", result);
            return result;
        }

        std::string result = recv_buffer;
        recv_buffer.clear();
        size_t needed = bytes_to_read - result.length();
        std::vector<char> temp_buf(needed);

        size_t total_received = 0;
        while(total_received < needed) {
            ssize_t bytes_this_call = recv(sockfd, temp_buf.data() + total_received, needed - total_received, 0);
            if (bytes_this_call <= 0) throw std::runtime_error("Connection closed while waiting for data.");
            total_received += bytes_this_call;
        }

        result.append(temp_buf.data(), total_received);
        print_hex_dump("DATA (FROM SOCKET)", std::string(temp_buf.data(), total_received));
        return result;
    }

    // Эта функция теперь просто ищет '\n' в буфере, чтобы найти конец пакета
    std::string receive_one_packet() {
        size_t end_of_packet_pos;
        while ((end_of_packet_pos = recv_buffer.find('\n')) == std::string::npos) {
            std::vector<char> temp_buf(1024);
            ssize_t bytes_this_call = recv(sockfd, temp_buf.data(), temp_buf.size(), 0);
             if (bytes_this_call <= 0) throw std::runtime_error("Connection closed while looking for packet end.");
            recv_buffer.append(temp_buf.data(), bytes_this_call);
             print_hex_dump("RECV RAW DATA INTO BUFFER", std::string(temp_buf.data(), bytes_this_call));
        }

        std::string packet = recv_buffer.substr(0, end_of_packet_pos + 1);
        recv_buffer.erase(0, end_of_packet_pos + 1);
        print_hex_dump("EXTRACTED PACKET FROM BUFFER", packet);
        return packet;
    }
    
public:
    std::string client_id; std::string password;
    Client(const std::string& h, uint16_t p,const std::string& id,const std::string& pass): host(h), port(p), client_id(id), password(pass){}
    ~Client() { if (sockfd != -1) close(sockfd); }

    void send_formatted_message(const std::string& header, const std::string& message) {
        if(DEBUG_MODE) std::cout << "[DEBUG] Preparing to send formatted message. Header: " << header << std::endl;
        std::string data_packet = ClientProtocol::build(header, client_id, -1, message);
        std::string length_packet = ClientProtocol::build("LENGTH", "client", -1, std::to_string(data_packet.size()));
        send_packet(length_packet);
        send_packet(data_packet);
    }
    
    ClientProtocol::ParsedMessage receive_formatted_message() {
        if(DEBUG_MODE) std::cout << "[DEBUG] Waiting for a formatted message (length + data)..." << std::endl;
        
        std::string length_packet_raw = receive_one_packet();
        
        ClientProtocol::ParsedMessage parsed_length_msg;
        parsed_length_msg = ClientProtocol::parse(length_packet_raw);
        if(parsed_length_msg.header != "LENGTH"){
            throw std::runtime_error("Protocol error: Expected LENGTH packet header, but got '" + parsed_length_msg.header + "'");
        }
        
        size_t payload_size = 0;
        try {
             payload_size = std::stoul(parsed_length_msg.message);
        } catch(const std::exception& e) {
            std::cerr << "[FATAL] Failed to convert length ('" << parsed_length_msg.message << "') to number. Error: " << e.what() << std::endl;
            throw; 
        }

        std::string payload_data = receive_data(payload_size);
        return ClientProtocol::parse(payload_data);
    }
    
    void connect_and_wait_for_welcome() {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) throw std::runtime_error("Failed to create socket.");
        sockaddr_in server_addr; server_addr.sin_family = AF_INET; server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) throw std::runtime_error("Invalid address.");
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) throw std::runtime_error("Failed to connect to " + host + ":" + std::to_string(port));
        std::cout << "[OK] Connected to server." << std::endl;
        
        if(DEBUG_MODE) std::cout << "[DEBUG] STEP 0: WAITING FOR CONN_ACCEPT" << std::endl;
        ClientProtocol::ParsedMessage welcome_msg = receive_formatted_message();
        if (welcome_msg.header == "CONN_ACCEPT") std::cout << "[SERVER] " << welcome_msg.message << std::endl;
        else if (welcome_msg.header == "CONN_REJECT") throw std::runtime_error("Connection rejected: " + welcome_msg.message);
        else throw std::runtime_error("Unexpected initial message from server: " + welcome_msg.header);
    }

    bool login() {
        std::cout << "\n--- Starting Login Process ---" << std::endl;
        if(DEBUG_MODE) std::cout << "[DEBUG] STEP 1: SENDING LOGIN" << std::endl;
        send_formatted_message("LOGIN", "");
        
        if(DEBUG_MODE) std::cout << "[DEBUG] STEP 2: WAITING FOR CHALLENGE" << std::endl;
        ClientProtocol::ParsedMessage challenge_msg = receive_formatted_message();
        if (challenge_msg.header != "CHALLENGE") { 
            std::cerr << "Login failed. Server response: " << challenge_msg.header << " - " << challenge_msg.message << std::endl; 
            return false; 
        }
        std::string nonce = challenge_msg.message; std::cout << "[RECV] Challenge nonce: " << nonce << std::endl;
        
        if(DEBUG_MODE) std::cout << "[DEBUG] STEP 3: SENDING RESPONSE" << std::endl;
        std::string response_hash = sha256(sha256(password) + nonce);
        send_formatted_message("RESPONSE", response_hash);
        
        if(DEBUG_MODE) std::cout << "[DEBUG] STEP 4: WAITING FOR AUTH_OK/FAIL" << std::endl;
        ClientProtocol::ParsedMessage auth_result = receive_formatted_message();
        if (auth_result.header == "AUTH_OK") { 
            std::cout << "[OK] " << auth_result.message << std::endl; 
            return true;
        } else { 
            std::cerr << "Login failed: " << auth_result.message << std::endl; 
            return false; 
        }
    }
};

void print_usage() { std::cout << "Usage: ./client <host> <port> <mode> <username> <password>\n" << "Modes:\n  login    - Log into an existing account.\n" << "  register - Register a new account.\n" << "Example: ./client 127.0.0.1 8080 login myuser mypassword123\n"; }

// Заглушка, так как в main эта функция не используется
void interactive_menu(Client& client) { (void)client; } 

int main(int argc, char* argv[]) {
    if (argc != 6) { print_usage(); return 1; }
    try {
        Client client(argv[1], std::stoul(argv[2]), argv[4], argv[5]);
        client.connect_and_wait_for_welcome();
        
        std::string mode = argv[3];
        if (mode == "login") {
            if (client.login()) {
                std::cout << "\nLogin successful! Interactive menu is disabled in debug mode." << std::endl;
            } else {
                 std::cerr << "\nLogin process failed." << std::endl;
            }
        } else if (mode == "register") {
            // Реализация регистрации
        } else {
             std::cerr << "Invalid mode" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL] Client stopped due to an error: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "\nClient finished." << std::endl;
    return 0;
}