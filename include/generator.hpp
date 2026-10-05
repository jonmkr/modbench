#include <thread>
#include <atomic>

void switchNetns(std::string nsName);

class ModbusTrafficGenerator {
public:
    ModbusTrafficGenerator();

    void startResponder();
    void stopResponder();
    void startController(const std::string & responderAddr);
    
private:
    std::thread controllerThread;
    std::thread responderThread;

    std::atomic<bool> stopResponderWorker;
    
    void responderTask();
    void controllerTask(const std::string& responderAddr);
};