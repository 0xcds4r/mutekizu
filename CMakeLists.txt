cmake_minimum_required(VERSION 3.20)
project(mutekizu VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQ REQUIRED IMPORTED_TARGET libnetfilter_queue)

add_library(dpi_core STATIC
    src/config.cpp
    src/log.cpp
    src/tls_clienthello.cpp
    src/tls_probe.cpp
    src/strategy.cpp
    src/netpacket.cpp
    src/nft_rules.cpp
    src/process.cpp
    src/doctor.cpp
    src/nfq_engine.cpp
)
target_include_directories(dpi_core PUBLIC src)
target_link_libraries(dpi_core PUBLIC PkgConfig::NFQ)
target_compile_options(dpi_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(mutekizu src/main.cpp)
target_link_libraries(mutekizu PRIVATE dpi_core)
target_compile_options(mutekizu PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(mutekizu PRIVATE MUTEKIZU_VERSION="${PROJECT_VERSION}")

# Test-only helper: a deliberately naive, stateless "DPI" used by the netns lab.
add_executable(dpi-model tests/dpi_model.cpp)
target_link_libraries(dpi-model PRIVATE dpi_core)

enable_testing()
add_executable(mutekizu-unit tests/unit_tls.cpp)
target_link_libraries(mutekizu-unit PRIVATE dpi_core)
add_test(NAME tls_and_strategy COMMAND mutekizu-unit)

# Synthetic DPI ladder for the adversarial arena.
add_library(arena_ladder STATIC tests/arena/ladder.cpp)
target_link_libraries(arena_ladder PUBLIC dpi_core)
add_executable(dpi-ladder tests/arena/dpi_ladder.cpp)
target_link_libraries(dpi-ladder PRIVATE arena_ladder)
add_executable(dpi-ladder-unit tests/arena/ladder_unit.cpp)
target_link_libraries(dpi-ladder-unit PRIVATE arena_ladder)
add_test(NAME dpi_ladder_unit COMMAND dpi-ladder-unit)

include(GNUInstallDirs)

option(MUTEKIZU_GUI "Build the Qt 6 desktop GUI" ON)
if(MUTEKIZU_GUI)
    find_package(Qt6 QUIET COMPONENTS Core Gui Network Quick Qml DBus QuickControls2)
    if(Qt6_FOUND)
        add_subdirectory(gui)
    else()
        message(STATUS "Qt6 GUI dependencies not found; skipping mutekizu-gui")
    endif()
endif()

install(TARGETS mutekizu RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES config/mutekizu.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/mutekizu)
install(FILES config/domains.txt DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/mutekizu)
install(FILES systemd/mutekizu.service DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
