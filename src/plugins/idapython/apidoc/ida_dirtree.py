"""Types involved in grouping of item into folders.

The dirtree_t class is used to organize a directory tree on top of any collection that allows for accessing its elements by an id (inode).
No requirements are imposed on the inodes apart from the forbidden value -1 (used to denote a bad inode).
The dirspec_t class is used to specialize the dirtree. It can be used to introduce a directory structure for:
* local types
* structs
* enums
* functions
* names
* etc"""
