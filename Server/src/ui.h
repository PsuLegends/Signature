
#pragma once
#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include <vector>
#include "communicator.h"
#include "error.h"
#include "logger.h"
namespace po = boost::program_options;
class UI
{
private:
    uint port;
    std::string base_loc;
public:
    logger log;
    po::options_description desc;
    po::variables_map vm;
    std::string log_loc;
    UI(int argc, char* argv[]);
    uint get_port();
    std::string get_log_loc();
};