#include <fcntl.h>
#include <bitset>
#include <random>

#include <modbus/modbus-tcp.h>

#include <generator.hpp>
#include <logger.hpp>

void switchNetns(std::string nsPath) {
    int fd = open(nsPath.c_str(), O_RDONLY);
    if (fd == -1) {
        Logger::getInstance().log(ERROR, "Failed to open netns descriptor");
        return;
    }

    if (setns(fd, CLONE_NEWNET) == -1) {
        Logger::getInstance().log(ERROR, "Failed to change netns");
        close(fd);
        return;
    }

    close(fd);
}

ModbusTrafficGenerator::ModbusTrafficGenerator() {}

void ModbusTrafficGenerator::startResponder() {
    responderThread = std::thread(&ModbusTrafficGenerator::responderTask, this);
}

void ModbusTrafficGenerator::stopResponder() {
    stopResponderWorker = true;
    responderThread.join();
}

void ModbusTrafficGenerator::responderTask() {
    switchNetns("/run/netns/ue");

    modbus_mapping_t* mapping = modbus_mapping_new(500, 500, 500, 500);

    modbus_t* ctx = modbus_new_tcp(NULL, 502);

    int socket = modbus_tcp_listen(ctx, 1);
    if (socket == -1) {
        Logger::getInstance().log(ERROR, std::format("Failed to open socket: {}", modbus_strerror(errno)));
        return;
    }

    while (!stopResponderWorker){
        int conn = modbus_tcp_accept(ctx, &socket);
        if (conn == -1) {
            Logger::getInstance().log(ERROR, "Responder failed to accept connection");
        } else {
           Logger::getInstance().log(INFO, "Connection from controller accepted");
        }

        while (true) {
            uint8_t* req = new uint8_t[MODBUS_TCP_MAX_ADU_LENGTH];
            int len = modbus_receive(ctx, req);
            if (len == -1) {
                Logger::getInstance().log(ERROR, "End of stream, closing connection");
                break;
            } else {
                modbus_reply(ctx, req, len, mapping);
            }
            
        }
    }

}

void ModbusTrafficGenerator::startController(const std::string & responderAddr) {
    controllerThread = std::thread(&ModbusTrafficGenerator::controllerTask, this, responderAddr);
    controllerThread.join();
}

void ModbusTrafficGenerator::controllerTask(const std::string& responderAddr) {
    
    modbus_t* ctx = modbus_new_tcp(responderAddr.c_str(), 502);

    int connected;
    for (int i = 0; i < 3; i++) {
        connected = modbus_connect(ctx);

        if (connected == 0) {
            Logger::getInstance().log(INFO, "Controller connected successfully");
            break;
        } else {
            Logger::getInstance().log(DEBUG, "Controller failed to connect, retrying");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    if (!connected == -1) {
        Logger::getInstance().log(ERROR, std::format("Controller failed to connect: {}", modbus_strerror(errno)));
        return;
    }


    while (true) {
        int sent = modbus_write_bit(ctx, 0, true);
        if (sent == -1) {
            Logger::getInstance().log(ERROR, "Failed to send instructions");
        }
    }


    modbus_close(ctx);
    modbus_free(ctx);
}