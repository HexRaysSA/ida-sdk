
Welcome to the Hex-Rays Decompiler SDK!
---------------------------------------

We are happy to present you the programmatic API for the decompiler.
This version gives you an idea of the overall SDK structure and
provides a base to build on. Currently only the decompilation results
and the user interface are accessible, later we will add low level
stuff and make the decompiler portable. Today you can:

  - decompile a function or arbitrary chunk of code and get a ctree.
    A ctree is a data structure that represents the decompilation result.

  - modify the ctree the way you want. You can rearrange
    statements, optimize expressions, add or remove variables, etc.

  - add a new item to the popup menu, react to user actions like
    keyboard, mouse clicks, etc.

  - hook to the decompilation events and modify the decompilation result
    on the fly.

  - generate microcode for a function or arbitrary chunk of code
    and use the results of data flow analysis.

  - install new microcode optimization rules in order to improve the output.

You will need the latest IDA SDK to compile the plugins. The
decompiler SDK consists of one single file: include\hexrays.hpp To
install the decompiler SDK, just copy this file to the include
directory of the IDA SDK.

There is no .lib file. You will compile and link plugins for the
decompiler the same way as plugins for IDA. For a quick start, please
copy the sample plugins to the plugins subdirectory of the SDK and
compile them. We tested the SDK with two compilers: Visual Studio and
Borland but other compilers should work too.

We will not guarantee backward compatibility at the early stages but
as soon as things settle down, we will switch to that mode.

There are a few sample plugins. Below are their descriptions.

Sample 1
--------

  This plugin decompiles the current function and prints the result in
  the message window. It is useful to learn how to initialize a
  decompiler plugin. Please note that all decompiler sample plugins
  have the "hexrays_" prefix in their names. This is done to make sure
  that the decompiler plugins are loaded after the hexrays plugin.
  Otherwise they would see that the decompiler is missing and
  immediately terminate.

  We recommend you to keep the same naming scheme: please use the
  "hexrays_" prefix for your decompiler plugins.

  N.B.: if you're writing a plugin for non-x86 version of the decompiler,
  you should use another prefix. For example, the x64 decompiler is
  named "hexx64", ARM is "hexarm" and so on. To be certain, check IDA's
  "plugins" directory. To debug plugin loading issues, you can use -z20
  switch when running IDA.


Sample 2
--------

  This plugin shows how to hook to decompiler events and react to
  them. It also shows how to visit all ctree elements and modify them.

  This plugin waits for the decompilation result to be ready and
  replaces zeroes in pointer contexts with NULLs. One might say that
  this is just cosmetic change, but it makes the output more readable.

  Since the plugin hooks to events, it is fully automatic. The user
  can disable it by selecting it from the Edit, Plugins menu.

Sample 3
--------

  This plugin shows

    - how to add a new popup menu item
    - how to map the cursor position to ctree element
    - how to modify ctree
    - how to make the changes persistent

  This is a quite complex plugin but it is thoroughly commented.

Sample 4
--------

  This plugin dumps all user-defined information to the message window.
  Read the source code to learn how to access various user-defined
  data from your plugins:

    - label names
    - indented comments
    - number formats
    - local variable names, types, comments

Sample 5
--------

  This plugin generates a graph from the current pseudocode
  and displays it with wingraph32.

  The source code can be used to learn ctree details.


Sample 6
--------

  This plugin modifies the decompilation output: removes some space characters.

  The source code can be used to learn the output text.


Sample 7
--------

  This plugin demonstrates how to use the cblock_t::iterator class.
  It enumerates all instructions of a block statement.


Sample 8
--------

  This plugin demonstrates how to use the udc_filter_t
  (User-Defined Call generator) class, which allows replacing
  cryptic function calls, with a simpler/more-readable counterpart.


Sample 9
--------

  This plugin demonstrates how to generate microcode for a given function
  and print it into the output window. It displays fully optimized microcode
  but it is also possible to retrieve microcode from earlier stages of
  decompilation.
  Generating the microcode text should be used only for debugging purposes.
  Printing microcode in production code may lead to crashes or wrong info.


Sample 10
---------

  This plugin installs a custom microcode optimization rule:
    call   !DbgRaiseAssertionFailure <fast:>.0
  =>
    call   !DbgRaiseAssertionFailure <fast:"char *" "assertion text">.0

 See also sample19 for another example.

Sample 11
---------

  This plugin installs a custom inter-block optimization rule:

    goto L1     =>        goto L@
    ...
  L1:
    goto L2

  In other words we fix a goto target if it points to a chain of gotos.
  This improves the decompiler output is some cases.


Sample 12
---------

  This plugin displays list of direct references to a register from the current
  instruction.


Sample 13
---------

  This plugin generates microcode for selection and dumps it to the output window.


Sample 14
---------

  This plugin shows xrefs to the called function as the decompiler output.
  All calls are displayed with the call arguments.


Sample 15
---------

  This plugin shows list of possible values of a register using
  the value range analysis.

Sample 16
---------

  This plugin installs a custom instruction optimization rule:

    mov #N, var.4                  mov #N, var.4
    xor var@1.1, #M, var@1.1    => mov #NM, var@1.1
                                     where NM == (N>>8)^M

  We need this rule because the decompiler cannot propagate the second
  byte of VAR into the xor instruction.

  The XOR opcode can be replaced by any other, we do not rely on it.
  Also operand sizes can vary.

Sample 17
---------

 This plugin shows how to use "Select offsets" widget (select_udt_by_offset() API).
 This plugin repeats the Alt-Y functionality.

Sample 18
---------

 This plugin shows how to specify a register value at a desired location.
 Such a functionality may be useful when the code to decompile is
 obfuscated and uses opaque predicates.

Sample 19
---------

 This plugin shows how to install a custom microcode optimization rule.
 Custom rules are useful to handle obfuscated code.
 See also sample10 for another example.

Sample 20
---------

 This plugin shows how to modify the decompiler output on the fly by
 adding dynamic comments.

It is also possible to write decompiler plugins or scripts in Python.
In fact we ship most of the above plugins as examples,
see the python/examples/hexrays subdirectory of your IDA installation.

Enjoy the SDK!
Hex-Rays

------------------------------------------------------------------
Annex 1: a brief description of ctree

Ctree is a data structure that keeps the decompilation result. As the name
implies, it is a tree-like structure. At the top level, we have the cfunc_t class.
This class describes the function and gives access to its attributes: its type,
local variables, maturity level, and body.

The ctree class is not created in one transaction but built
progressively: it starts with an empty class, then a rough function
body is created, then it is modified in several steps. You can
intercept control at any intermediate stage (maturity level) but be
prepared that the ctree does not look quite normal. Only at the final
stage the ctree is syntactically correct and has non-trivial type
information.

The most interesting part of the cfunc_t class is the function body
(this part of the data structure is called ctree). The function body
consists of citem_t elements. In fact, citem_t is an abstract class
and its pure instances must never be created. There are two citem_t
flavors (derived classes):

  - cinsn_t: a statement
  - cexpr_t: an expression

Please look up the class definitions in the header file. citem_t elements
can be reference each other. For example "x+y*3" is represented as:

         cot_add
          /     \
         /       \
    cot_var:x     cot_mul
                  /      \
                 /        \
              cot_var:y  cot_num:3


This is a very simplified diagram but hopefully it gives an idea how
the tree is organized.

Each ctree item may have a label. Each ctree item is mapped to an
address in the program. Please note that in some cases several items
may have the same address. If we want to denote a citem_t, we cannot
store a pointer to it because at the next moment (as soon as we yield
control) another plugin or the decompiler itself might shuffle the
tree. We recommend to denote ctree items by their addresses and types.
Addresses can be safely stored in the database (in fact, it is better
to store offsets from the function entry point; this will make the
information relocatable) and reused in subsequent IDA sessions.

Expressions (cexpr_t) have a type string attached to them. By type
here we mean a C language type (int, char *, etc). The expression
types must be consistent. For example, if in the above example "x" is
a pointer, then the type of the whole expression must be the same
pointer. y cannot be a pointer because it is an operand of the
multiplication operation.

To facilitate ctree processing, you can use the ctree_visitor_t class
or any of its derived classes. These classes make ctree traversal
really easy. However, if ctree gets modified during the traversal,
some precautions must be taken. For example, if a parent of the
currently visited item is modified, the traversal must be stopped. See
the sample plugins for a real use of these classes.

You  are  free  to modify the ctree the way you want but you must keep
some rules in mind:

  - ctree must be consistent. For example, cot_add (the addition
    operator) requires 2 operands. You must not create a cot_add
    item with another number of operands.

  - expression types (like char*, int, etc) must be consistent. If you
    modify an expression and change its type, then the types of all parent
    expressions must be recalculated. You can use the recalc_parent_types()
    function to that. If this function returns true, then the current ctree
    traversal must be terminated (and restarted if necessary).

  - you are free to change the ctree (replace cot_add by cot_sub, for example)
    but the results won't correspond to the disassembly. you are responsible for
    your changes.

You can verify the ctree by calling the cfunc_t::verify() function. If anything
is wrong, it will stop with an interr.

------------------------------------------------------------------
Annex 2: a brief description of microcode

Microcode is represented by the mba_t class. This object contains
global information about the microcode and a list of basic blocks.
Basic blocks can be accessed in two ways:

  - as a vector (by an index), using get_mblock()
  - as a double linked list, using the blk->nextb and blk-prevb expressions

Each basic block is represented by the mblock_t class.
The most important attributes of a basic block are:
  - block type (1way,2way,nway,etc)
  - serial (block index, >=0)
  - head/tail pointers to the double linked list of instructions
  - predset/succset: predecessors and successors of the block in the control flow graph
  - various lists (use-list, def-list, etc)

Each instruction is represented by the minsn_t class. All instructions have:
  - an opcode
  - 3 operands: l, r, d (left, right, destination)
  - address (ea)
  - properties (various bits)

There are convenience functions to walk over all instructions or operands.
See for_all...() functions.

Data-based search functions exist in 2 flavors:

  - inside a basic block. see member functions of mblock_t, like find_first_use()
  - global search. see mbl_graph_t::is_accessed_globally()

In order to build the lists required by the above functions, use
  - for entire instruction: build_use_list(), build_def_list()
  - for one operand: append_use_list(), append_def_list()

It is okay to modify the microcode by adding or removing instructions.
See insert_into_block() and remove_from_block(). Also you can modify the existing
instructions or operand by directly modifying any of their fields.

Since it is very easy to end up with inconsistent microcode after modifying it,
we publish the source code of consistency verifiers. There are 2 verifiers:

  - verify.cpp: microcode verifier
  - cverify.cpp: ctree verifier

These files are not meant to be compiled into your plugins. Instead you should
call one of the following functions after modifying microcode or ctree:

  - mba_t::verify(bool always);
  - ctree_t::verify(allow_unused_labels_t aul, bool even_without_debugger);

The source files should be used to understand the meaning of the internal error
code that will occur if the microcode or ctree become inconsistent.

We also publish a file called showmic.cpp. It can be used to learn how the
microcode objects are converted into text.

