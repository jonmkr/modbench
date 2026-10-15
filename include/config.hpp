#include <unordered_map>
#include <string>

class Config : public std::unordered_map<std::string, std::string> {
public:
    static Config& getInstance() {
        static Config instance;
        return instance;
    }

private:
    Config(){};
};