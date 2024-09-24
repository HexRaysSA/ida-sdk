IDA Plugin Project Template:
============================

IDAPlugin is a Visual Studio C++ Project template.

This template can be used for x64 platform with the following configurations:

* x64 - Debug: will produce debug plugins for IDA64
* x64 - Realease: will produce release plugins for IDA64

Installation:
-------------

* It it does not exist create IDASDK environment variable. Make it point to the 
  IDA SDK root directory. The generated projects will use it find the include,
  library and binary output directories.
* Copy IDAPlugin.zip in $(VisualStudioDir)\Templates\ProjectTemplates\Visual 
  C++ Projects
* Start Visual Studio
* Create a new project. If the new project template does not appear, Type IDA
  in the search for template edit box.
* Once the new project has been created, check the selected toolset in project
  property page, general section. If not change it for every x64 configuration.
* At this stage you should be able to compile your project.

Troubleshooting
---------------

It is possible that Visual Studio does not properly update its cache. In order
to solve that follow these steps:

* Open a Visual Studio Command Prompt as Administator and execute
```
devenv /installvstemplates
```

* If Visual Studio still not show the new template try:
```
devenv /updateconfiguration
```