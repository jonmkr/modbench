#include <thread>

void switchNetns(std::string nsName);

class ModbusTrafficGenerator {
public:
    ModbusTrafficGenerator();

    void startResponder();
    void startControlling();
    
private:
    std::thread controllerThread;
    std::thread responderThread;
    
    void responderTask();
    void controllerTask(const std::string& responderAddr);
};