cmake_minimum_required(VERSION 3.15)
project(json_signer)

find_package(nlohmann_json REQUIRED)
find_package(libsodium REQUIRED)
find_package(CLI11 REQUIRED)
find_package(spdlog REQUIRED)

add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME}
    nlohmann_json::nlohmann_json
    libsodium::libsodium
    CLI11::CLI11
    spdlog::spdlog
)