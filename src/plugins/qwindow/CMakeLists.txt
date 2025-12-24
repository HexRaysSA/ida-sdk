ida_add_plugin(qwindow
    TYPE QT
    QT_COMPONENTS Core Gui Widgets
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

# Only set compile options if target was created (Qt found)
if(TARGET qwindow AND MSVC)
    target_compile_options(qwindow PRIVATE /GR)
endif()
