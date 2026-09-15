cmake_minimum_required(VERSION 3.10)

project(ModBench LANGUAGES CXX)

find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMODBUS REQUIRED IMPORTED_TARGET libmodbus)

add_executable(controller controller.cpp)

target_link_libraries(controller PRIVATE PkgConfig::LIBMODBUS)
target_link_libraries(controller PRIVATE PcapPlusPlus::Pcap++)

