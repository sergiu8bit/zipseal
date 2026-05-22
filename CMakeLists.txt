cmake_minimum_required(VERSION 3.10)
project(zipseal LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

# --- Dependencies ---
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBZIP REQUIRED IMPORTED_TARGET libzip)
find_package(GTest REQUIRED)

# --- Libraries ---
add_library(zipseal_static STATIC ${SOURCES})
target_include_directories(zipseal_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(zipseal_static PROPERTIES OUTPUT_NAME "zipseal")
target_link_libraries(zipseal_static PUBLIC OpenSSL::Crypto PkgConfig::LIBZIP)

add_library(zipseal_shared SHARED ${SOURCES})
target_include_directories(zipseal_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(zipseal_shared PROPERTIES OUTPUT_NAME "zipseal")
target_link_libraries(zipseal_shared PUBLIC OpenSSL::Crypto PkgConfig::LIBZIP)

# Position-independent code is required for shared libraries
set_target_properties(zipseal_shared PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(zipseal_static PRIVATE -Wall -Wextra -Werror)
target_compile_options(zipseal_shared PRIVATE -Wall -Wextra -Werror)

# --- Unit Tests ---
enable_testing()

file(GLOB TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp)

add_executable(unit_tests ${TEST_SOURCES})
target_link_libraries(unit_tests PRIVATE
    zipseal_static          # already brings OpenSSL + libzip transitively (PUBLIC link)
    GTest::gtest
    GTest::gtest_main
    pthread
)

add_test(NAME unit_tests COMMAND unit_tests)

# --- Install Rules ---
install(TARGETS zipseal_static zipseal_shared
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)