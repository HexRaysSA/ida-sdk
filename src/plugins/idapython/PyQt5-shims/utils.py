"""This module provides few additional utilities to be used in PyQt5 shim
internally"""
import inspect
import os
import warnings

from enum import Enum, EnumMeta, IntEnum, IntFlag
from pathlib import Path

import idaapi

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QMessageBox
    _pyside_ok = True
except (ModuleNotFoundError, ImportError):
    _pyside_ok = False



USER_CFG_FOLDER = Path(idaapi.get_ida_subdirs("cfg")[0])
USER_CFG = USER_CFG_FOLDER / "idapython.cfg"
DIRECTIVE = "IDAPYTHON_USE_PYQT5_SHIM"
ENABLE_FLAG = os.environ.get(DIRECTIVE)

MIGRATION_URL = "https://docs.hex-rays.com/" \
    "user-guide/plugins/migrating-pyqt5-code-to-pyside6"
MIGRATION_MSG = f"More information here {MIGRATION_URL}"

_BITWISE_WARNING = "This bitwise operation relies on a PyQt5 shim feature. " \
    "If PyQt5 is not imported, it won't work. " \
    "For PySide6, use <EnumOrFlag>.value for bitwise operations instead"


def _patch(obj, level=0):
    if not inspect.isclass(obj):
        return

    if not hasattr(obj, "__dir__"):
        return  # __dict__ doesn't work for PySide6 objects

    if isinstance(obj, EnumMeta):
        if issubclass(obj, (IntEnum, IntFlag)):  # Already support bitwise ops
            return

        obj.__or__ = patched_or
        return

    if level >= 2:
        return
    for attr in sorted(dir(obj)):  # Ensure order
        if attr.startswith("__"):  # Skip dunder attributes
            continue
        _patch(getattr(obj, attr), level+1)


def _clone_module(globals_dict, original_module):
    """Copy all non-dunder attributes to current module's global scope"""
    for attr in dir(original_module):
        if attr.startswith("__"):
            continue

        obj = getattr(original_module, attr)
        _patch(obj)
        globals_dict[attr] = obj


def patched_or(self, other):
    """Patched __or__ to perform bitwise OR between enum value and int"""
    if isinstance(other, int):
        warn_once_per_module(_BITWISE_WARNING)
        return self.value | other
    if isinstance(other, (Enum, EnumMeta)):
        if isinstance(other, type(self)):
            warn_once_per_module(_BITWISE_WARNING)
        return type(self)(self.value | other.value)
    return NotImplemented


def warn_once_per_module(message, *,  module_name=None):
    """
    Show a warning once per calling module, from the correct user code location
    """
    if module_name is None:
        module_name = __name__
    stack = inspect.stack()
    user_frame_index = 0

    # Find first frame outside the current module
    for i, frame_info in enumerate(stack):
        frame = frame_info.frame
        mod = inspect.getmodule(frame)
        mod_name = mod.__name__ if mod else ""
        if mod_name != module_name:
            user_frame_index = i
            break

    warnings.warn(message, RuntimeWarning, stacklevel=user_frame_index+1)


def are_shims_enabled() -> bool:
    """Check if shims are enabled"""
    env = os.environ.get(DIRECTIVE)
    return env and env != "0"


def are_shims_decided() -> bool:
    """Check if a decision has been made about the shims"""
    env = os.environ.get(DIRECTIVE)
    return bool(env)


def confirm_decision():
    """
    Ask question about enabling shims if the ENV or Directive are not present
    """
    if not _pyside_ok:
        raise NotImplementedError(
            "Can't import PySide6. Are you trying to use Qt without GUI?")
    msg_box = QMessageBox()
    msg_box.setWindowTitle("Confirmation PyQt5 shims")
    msg_box.setText(
        "<p>A script or plugin is attempting to load PyQt5, which has been "
        "deprecated in favor of PySide6 as part of IDA's move to Qt6.</p>"

        "<p>While we recommend porting existing code to PySide6, this version"
        " of IDA comes with \"PyQt5 shims\" - a compatibility layer that "
        "tries its best to support existing PyQt5-targeting code.</p>"
        f"<p>More information <a href='{MIGRATION_URL}'>here</a></p>"

        "<p>Do you want to enable PyQt5 shims?</p>"

        "<p>(Note: This decision can be reversed later, should you change "
        "your mind!)</p>"
    )
    msg_box.setTextFormat(Qt.TextFormat.RichText)
    msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    msg_box.setIcon(QMessageBox.Question)
    msg_box.setDefaultButton(QMessageBox.No)
    set_pyqt5_config(msg_box.exec() == QMessageBox.Yes)


def set_pyqt5_config(enable: bool):
    """Set pyqt5 directive in the user config file"""
    USER_CFG_FOLDER.mkdir(parents=True, exist_ok=True)

    if enable:
        msg1, msg2, value, unset_value = "enabled", "disable", "1", "0"
    else:
        msg1, msg2, value, unset_value = "disabled", "enable", "0", "1"

    with USER_CFG.open("a", encoding="utf-8") as file:
        file.write(f"\n#if __IDAVER__ >= 920\n{DIRECTIVE} = {value}\n#endif\n")

    print(
        f"PyQt5 shims are {msg1} in {USER_CFG}. To {msg2}, set "
        f"{DIRECTIVE} = {unset_value} in this file",
    )
    os.environ[DIRECTIVE] = value
