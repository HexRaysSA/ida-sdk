# IDAPython

## Python Plugin for IDA

IDAPython is an IDA plugin that enables you to write scripts
for IDA in the Python programming language. IDAPython provides full
access to both the IDA API and any installed Python module.

Check the scripts in the [examples](examples/index.md) directory to get a quick glimpse.

## Resources

- **Website**: [Hex-Rays Developer Guide - IDAPython](https://docs.hex-rays.com/developer-guide/idapython)
- **Forum**: [Hex-Rays API/SDK Forum](https://community.hex-rays.com/c/idas/api-sdk/15)
- **Support**: [Hex-Rays Support Portal](https://get.support.hex-rays.com/servicedesk/customer/portals)
- **Email**: [support@hex-rays.com](mailto:support@hex-rays.com)
- **API Reference**: [The Full Function Cross-Reference](https://python.docs.hex-rays.com)

## Installation from Binaries

Follow the steps in the [build instructions](BUILDING.md).

## Usage

- Run script: File / Script file (`Alt+F7`)
- Execute Python statement(s): (`Shift+F2`)
- Run previously executed script again: View / Recent Scripts (`Alt+F9`)

> **Note:** The shortcut `Alt+F7` for running scripts may conflict with GNOME's
> default keyboard settings, which use `Alt+F7` for window movement.
> If this occurs, you may need to [choose a different shortcut]
> (https://docs.hex-rays.com/user-guide/user-interface/menu-bar/options#shortcuts)
> for running the script, or adjust your GNOME keyboard settings.

### User Init File

You can place your custom settings in a file called `idapythonrc.py` that
should be placed in the
[IDAUSR](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/windows/environment-variables#idausr)
directory.

Linux/macOS:

```sh
${HOME}/.idapro/
```

Windows:

```cmd
%AppData%\Hex-Rays\IDA Pro
```

The user init file is read and executed at the end of the initialization process.

## Configuration

Like [other IDA components](https://docs.hex-rays.com/user-guide/configuration/configuration-files),
IDAPython can be configured using the configuration file `idapython.cfg`.


### idapyswitch

IDAPython requires a Python3+ installation in order to work.

Because different users might have different (and possibly multiple)
versions of Python3 installed, IDA comes with a tool called `idapyswitch`
that can be run to select the desired Python3 runtime.

If you selected IDAPython-for-Python3.x at the installation time,
the `idapyswitch` utility should already have been run and selected
the most appropriate Python3 version.

Should you want to switch to another Python3.x install after installation,
please run `idapyswitch` from the IDA directory. It will scan for Python
installs present in the system's standard locations and offer you to choose one.
It also supports optional command-line switches to handle non-standard installs.
Run `idapyswitch -h` to see them.

**Note:** There are plans for more modern python initialization and venv support

#### Mac

Mac users may get into trouble on Apple Silicon using idapyswitch, because codesigning rules are strictly enforced

See [docs/tbd.md](docs/tbd.md) in this case
