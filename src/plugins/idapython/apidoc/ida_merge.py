"""Merge functionality.

NOTE: this functionality is available in IDA Teams (not IDA Pro)
There are 3 databases involved in merging: base_idb, local_db, and remote_idb.
* base_idb: the common base ancestor of 'local_db' and 'remote_db'. in the UI this database is located in the middle.
* local_idb: local database that will contain the result of the merging. in the UI this database is located on the left.
* remote_idb: remote database that will merge into local_idb. It may reside locally on the current computer, despite its name. in the UI this database is located on the right. base_idb and remote_idb are opened for reading only. base_idb may be absent, in this case a 2-way merging is performed.


Conflicts can be resolved automatically or interactively. The automatic resolving scores the conflicting blocks and takes the better one. The interactive resolving displays the full rendered contents side by side, and expects the user to select the better side for each conflict.
Since IDB files contain various kinds of information, there are many merging phases. The entire list can be found in merge.cpp. Below are just some selected examples:
* merge global database settings (inf and other global vars)
* merge segmentation and changes to the database bytes
* merge various lists: exports, imports, loaded tils, etc
* merge names, functions, function frames
* merge debugger settings, breakpoints
* merge struct/enum views
* merge local type libraries
* merge the disassembly items (i.e. the segment contents) this includes operand types, code/data separation, etc
* merge plugin specific info like decompiler types, dwarf mappings, etc


To unify UI elements of each merge phase, we use merger views:
* A view that consists of 2 or 3 panes: left (local_idb) and right (remote_idb). The common base is in the middle, if present.
* Rendering of the panes depends on the phase, different phases show different contents.
* The conflicts are highlighted by a colored background. Also, the detail pane can be consulted for additional info.
* The user can select a conflict (or a bunch of conflicts) and say "use this block".
* The user can browse the panes as he wishes. He will not be forced to handle conflicts in any particular order. However, once he finishes working with a merge handler and proceeds to the next one, he cannot go back.
* Scrolling the left pane will synchronously scroll the right pane and vice versa.
* There are the navigation commands like "go to the prev/next conflict"
* The number of remaining conflicts to resolve is printed in the "Progress" chooser.
* The user may manually modify local database inside the merger view. For that he may use the regular hotkeys. However, editing the database may lead to new conflicts, so we better restrict the available actions to some reasonable minimum. Currently, this is not implemented.


IDA works in a new "merge" mode during merging. In this mode most events are not generated. We forbid them to reduce the risk that a rogue third-party plugin that is not aware of the "merge" mode would spoil something.
For example, normally renaming a function causes a cascade of events and may lead to other database modifications. Some of them may be desired, some - not. Since there are some undesired events, it is better to stop generating them. However, some events are required to render the disassembly listing. For example, ev_ana_insn, av_out_insn. This is why some events are still generated in the "merge" mode.
To let processor modules and plugins merge their data, we introduce a new event: ev_create_merge_handlers. It is generated immediately after opening all three idbs. The interested modules should react to this event by creating new merge handlers, if they need them.
While the kernel can create arbitrary merge handlers, modules can create only the standard ones returned by:
create_nodeval_merge_handler() create_nodeval_merge_handlers() create_std_modmerge_handlers()
We do not document merge_handler_t because once a merge handler is created, it is used exclusively by the kernel.
See mergemod.hpp for more information about the merge mode for modules.
"""
