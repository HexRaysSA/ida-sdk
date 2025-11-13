find_package(Qt6 QUIET COMPONENTS Core Gui Widgets)

if(NOT Qt6_FOUND)
    message(STATUS "Qt6 not found, skipping qwindow plugin")
    return()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

ida_add_plugin(qwindow
    SOURCES
        myactions.h
        qwindow.cpp
    DEFINES
        QT_NAMESPACE=QT
        QT_CORE_LIB
        QT_DLL
        QT_GUI_LIB
        QT_THREAD_SUPPORT
        QT_WIDGETS_LIB
)

target_link_libraries(qwindow PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

if(MSVC)
    target_compile_options(qwindow PRIVATE /GR)
endif()
