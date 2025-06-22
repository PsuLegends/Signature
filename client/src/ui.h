#pragma once
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include "show_error.h"
namespace po = boost::program_options;

class UI {
public:
    show_error debugger;
    po::options_description desc;
    po::variables_map vm;

    UI(int argc, char* argv[]);
    uint get_port();
    uint get_op();
    std::string check_path(std::string path, std::string function);
    std::string get_serv_ip();
    std::string get_username();
    std::string get_password();
    std::string get_in_file_location();
    std::string get_out_file_location();
    std::string get_user_data_location();
};
