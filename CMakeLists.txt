cmake_minimum_required(VERSION 3.1)

project(pingsim)
set (CMAKE_CXX_STANDARD 14)

include_directories(".")

add_executable(${PROJECT_NAME}
    "main_ping.cpp"
    "device_ping.cpp"
    "device_ping.h"
)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} ws2_32)
else()
    target_link_libraries(${PROJECT_NAME} pthread)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION bin)