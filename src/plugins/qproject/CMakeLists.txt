ida_add_plugin(qproject
    TYPE QT
    QT_COMPONENTS Core Gui Widgets OpenGL OpenGLWidgets
    SOURCES
        edge.cpp
        edge.h
        graphwidget.cpp
        graphwidget.h
        node.cpp
        node.h
        qproject.cpp
    DEFINES
        QT_NAMESPACE=QT
        QT_CORE_LIB
        QT_DLL
        QT_GUI_LIB
        QT_THREAD_SUPPORT
        QT_WIDGETS_LIB
)

# Only set compile options if target was created (Qt found)
if(TARGET qproject AND MSVC)
    target_compile_options(qproject PRIVATE /GR)
endif()
