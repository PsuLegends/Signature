#pragma once
#include <boost/program_options.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include "../Error/error.h"
namespace po = boost::program_options;
class UI {
public:
    UI(int argc, char* argv[]);
    uint16_t get_port() const;
    std::string get_serv_ip() const;
    std::string get_username() const;
    std::string get_password() const;
    uint get_op() const;

private:
    po::options_description desc;
    po::variables_map vm;
};