cmake_minimum_required(VERSION 3.9)
cmake_policy(SET CMP0042 NEW)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(BUILDING_NODE_EXTENSION)
add_compile_definitions(NAPI_EXPERIMENTAL)
add_compile_definitions(UNICODE)
add_compile_definitions(_UNICODE)

project(winapi)
include_directories(${CMAKE_JS_INC})
file(GLOB SOURCE_FILES "src/*.cpp" "src/*.h")
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

# Include Node-API wrappers
execute_process(COMMAND node -p "require('node-addon-api').include"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE NODE_ADDON_API_DIR
        )
string(REGEX REPLACE "[\r\n\"]" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})

target_include_directories(${PROJECT_NAME} PRIVATE ${NODE_ADDON_API_DIR})

# define NAPI_VERSION
if (DEFINED ENV{napi_build_version})
#add_definitions(-DNAPI_VERSION=${napi_build_version})
add_compile_definitions(NAPI_VERSION=${napi_build_version})
else()
#add_definitions(-DNAPI_VERSION=${napi_build_version})
add_compile_definitions(NAPI_VERSION=4)
endif()
