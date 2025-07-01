#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <chrono>
#include <cstring>
#include "../Error/error.h"
#include <mutex>
#include <boost/filesystem.hpp>
class logger{
    public:
    std::ofstream log;
    std::mutex mtx;
    int write_log(std::string log_loc,std::string message);
};