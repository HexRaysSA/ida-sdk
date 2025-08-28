# IDAPython
## Python plugin for IDA

IDAPython is an IDA plugin which makes it possible to write scripts
for IDA in the Python programming language. IDAPython provides full
access to both the IDA API and any installed Python module.

Check the scripts in the [examples](examples/index.md) directory to get an quick glimpse.

## Resources

The full function cross-reference is readable online at
  https://python.docs.hex-rays.com

## Installation from binaries

1. Install latest Python 3.x version from https://www.python.org/
2. Copy the whole "python" directory to `%IDADIR%`
3. Copy "idapython.cfg" to `%IDADIR%\cfg`

## Usage

 - Run script: File / Script file (`Alt+F7`)
 - Execute Python statement(s) (`Shift+F2`)
 - Run previously executed script again: View / Recent Scripts (`Alt+F9`)

### Batch mode execution:

Start IDA with the following command line options:
```
 -A -OIDAPython:yourscript.py file_to_work_on
 ```
or
```
-Syourscript.py
```
or
```
-S"yourscript.py arg1 arg2 arg3"
```

(Please see https://hex-rays.com/blog/running-scripts-from-the-command-line-with-idascript/)

If you want fully unattended execution mode, make sure your script
exits with a `qexit()` call.

By default scripts run after the database is opened. Extended option
format is:
```
  -OIDAPython:[N;]script.py
```
Where N can be:
  0: run script after opening database (default)
  1: run script when UI is ready
  2: run script immediately on plugin load (shortly after IDA starts and before processor modules and loaders)

### User init file

You can place your custom settings to a file called `idapythonrc.py`
that should be placed to
```sh
${HOME}/.idapro/
```
or
```cmd
%AppData%\Hex-Rays\IDA Pro
```
The user init file is read and executed at the end of the init process.

Please note that IDAPython can be configured with `idapython.cfg` file.


