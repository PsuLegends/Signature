#pragma once
#include <stdexcept>
#include <string>

class critical_error:public std::runtime_error{
    public:
    critical_error(const std::string& s):std::runtime_error(s){}
};