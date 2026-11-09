IDA as Library
================

Prerequisites

* IDA Pro Installation
   - Ensure you have IDA Pro version 9 or newer installed on your computer
   - Launch IDA at least once to read and accept the license terms

C++ SDK
=======
To use the ida library from the C++, please refer to the idalib.hpp header file shipped with C++ SDK where you will find the relevant information.


Python SDK
==========

To use the ida library Python module, you need to install and configure `idapro` package by following these steps:

* Install ida library Python Module
   - Navigate to the `idalib/python` folder within the IDA Pro installation directory
   - Run the command: `pip install .`

Setting Up the ida library Python Module
----------------------------------------

* Run the Activation Script
   - You need to inform the `idapro` Python module of your IDA Pro installation. To do this, run the `py-activate-idalib.py` script located in your IDA Pro installation folder:
     ```
     python /path/to/IDA/installation/py-activate-idalib.py [-d /path/to/active/IDA/installation]
     ```
     If the `-d` option is omitted, the script will automatically select the IDA installation folder from which it was executed.

Using the ida library Python Module
-----------------------------------

* Import `idapro` in your script
   - Make sure to import the `idapro` package as the first import in your Python script
   - After importing, you can utilize the existing ida Python APIs

Example Script
--------------

   - To give you an idea of how to use the `ida` module, you can check the `idalib/examples` folder in the IDA Pro installation directory

Note
----

   - Please make sure that the `idapro` module is always the first import in your script
