#include <unordered_map>
#include <string>
#include <fstream>
#include <ranges>
#include <iostream>
#include <cerrno>
#include <cstring>

class Config : public std::unordered_map<std::string, std::string> {
public:
    static Config& getInstance() {
        static Config instance;
        return instance;
    }

    bool loadConfig(std::string filename) {
        std::ifstream file(filename);

        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.size()) {
                size_t pos = line.find('=');
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                insert({key, value});
            }
        }

        file.close();
        return true;

    }

private:
    Config(){};
};