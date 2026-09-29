cmake_minimum_required(VERSION 3.10)

project(ModBench LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBMODBUS REQUIRED IMPORTED_TARGET libmodbus)

add_executable(controller controller.cpp logger.cpp)

target_include_directories(controller PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(controller PRIVATE PkgConfig::LIBMODBUS)
target_link_libraries(controller PRIVATE PcapPlusPlus::Pcap++)

