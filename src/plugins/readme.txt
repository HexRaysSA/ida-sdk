

        This directory contains sample plugin modules for IDA.

        Plugin modules are accessible by the user in two ways:

                - they appear as menu items in menu Edit|Plugins
                - they can be invoked by hotkeys

        A plugin has full access to the database and can interact with
        the user.

        IDA looks for plugins in PLUGINS subdirectory.
        In this directory there is also a configuration file.
        It is not necessary for a plugin to appear in the configuration file.
        Even if a plugin is not there IDA will load it.
        The configuration file allows the user to reassign the hotkeys,
        to change the plugin name as it appears in the menu or to change
        the argument passed to the plugin.

        A plugin has one exported entry (it should have the "PLUGIN" name).
        The entry is a plugin descriptor (plugin_t).
        It contains pointers to the following functions:

                - init: is called when the plugin is loaded
                - run:  is called when the user calls the plugin
                - term: is called before the plugin is unloaded

        run() function is the function which will do the real work.
        It has full access to the database (see include files for the
        description of IDA API). Also it can interact with the user
        (most of these functions are in kernwin.hpp file).


