# How to add merge functionality to plugin

To support IDA Teams a plugin must implement the logic for merging databases.
For that, the plugin must provide the description of the data to be merged
and ask the kernel to create merge handlers based on these descriptions.
The kernel will use the created handlers to perform merging and to display
merged data to the users. The plugin can implement callback functions to modify
some aspects of merging, if necessary.

## Plugin

The sample plugin without the merge functionality consists of two files:

    mex.hpp
    mex_impl.cpp

It is a regular implementation of a plugin which stores data in database.
Check the files for more info.

We demonstrate several approaches to add the merge functionality.
They are implemented in different directories mex1/, mex2/, and so on.

The "MEX_N" macros that are defined in makefile are used to parameterize
the plugin implementation, so that all plugin examples may be used simultaneously.

You may check the merge results for the plugins in one session of IDA Teams.
Obviously you should prepare databases by running plugins before launching of
IDA Teams session.

## Merge functionality

The merge functionality is implemented in the merge.cpp file. It contains
create_merge_handlers(), which is responsible for the creation of merge handlers.

Variants:
  * mex1/ Merge values stored in netnodes.
          The kernel will read the values directly from netnodes, merge them,
          and write back. No further actions are required from the plugin.
          If data is stored in a simple way using altvals or supvals,
          this simple approach is recommended.

  * mex2/ Merge values stored in variables.
          For more complex data that is not stored in a simple way in netnodes,
          (for example, data that uses database blobs), the previous approach
          cannot be used. This example shows how to merge the data that is
          stored in variables, like fields of the plugin context structure.
          The plugin provides the field descriptions to the kernel, which
          will use them to merge the data in the memory. After merging,
          the plugin must save the merged data to the database.
  * mex3/ Use mex1 example and learn how to improve UI look.
  * mex4/ Merge data stored in netnode blob.
          Usually blob data is displayed as a sequence of hexadecimal digits
          in merge chooser column.
          We show how to display blob contents in detail pane.





