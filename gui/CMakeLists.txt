cmake_minimum_required(VERSION 3.20)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Network Quick Qml DBus QuickControls2)

qt_standard_project_setup()
qt_policy(SET QTP0001 NEW)

set_source_files_properties(qml/Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_executable(mutekizu-gui
    src/main.cpp
    src/backend.cpp
    src/backend.hpp
)

qt_add_qml_module(mutekizu-gui
    URI Mutekizu
    VERSION 1.0
    RESOURCE_PREFIX "/qt/qml"
    QML_FILES
        qml/Main.qml
        qml/Theme.qml
        qml/Card.qml
        qml/NavButton.qml
        qml/StatusBadge.qml
        qml/OverviewPage.qml
        qml/DomainsPage.qml
        qml/SettingsPage.qml
        qml/DiagnosticsPage.qml
        qml/LogsPage.qml
        qml/AboutPage.qml
)

target_link_libraries(mutekizu-gui PRIVATE
    Qt6::Core Qt6::Gui Qt6::Network Qt6::Quick Qt6::Qml Qt6::DBus Qt6::QuickControls2
)
target_compile_definitions(mutekizu-gui PRIVATE
    MUTEKIZU_VERSION="${PROJECT_VERSION}"
)
target_compile_options(mutekizu-gui PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(mutekizu-gui PROPERTIES OUTPUT_NAME mutekizu-gui)

# Narrow privileged config writer. It is never setuid; it is expected to be run
# through pkexec (Polkit) and writes only the three fixed mutekizu files.
qt_add_executable(mutekizu-config-helper helper/helper.cpp)
target_link_libraries(mutekizu-config-helper PRIVATE Qt6::Core Qt6::Network)
target_compile_options(mutekizu-config-helper PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(mutekizu-config-helper PROPERTIES OUTPUT_NAME mutekizu-config-helper)

include(GNUInstallDirs)
install(TARGETS mutekizu-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS mutekizu-config-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
install(FILES mutekizu.desktop DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
install(FILES icons/mutekizu.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)

enable_testing()
add_test(NAME gui_backend_self_test COMMAND mutekizu-gui --self-test)
set_tests_properties(gui_backend_self_test PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software")
add_test(NAME gui_screenshot_smoke COMMAND mutekizu-gui --demo
         --screenshot ${CMAKE_CURRENT_BINARY_DIR}/gui-smoke.png --page overview)
set_tests_properties(gui_screenshot_smoke PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software")
add_test(NAME gui_helper_check
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/helper-check.sh
                 $<TARGET_FILE:mutekizu-config-helper>)
