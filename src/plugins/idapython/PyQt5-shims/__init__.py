"""This module is the shim for PyQt5 which is deprecated in favor of PySide6"""
import os
from . import utils

if not utils.are_shims_decided():
    utils.confirm_decision()

if not utils.are_shims_enabled():
    raise ImportError(
        f"PyQt5 is deprecated in favor of PySide6. You see that error because "
        f"you decided to disable PyQt5 shims. Set `{utils.DIRECTIVE} = 1` "
        f"in {utils.USER_CFG} to enable PyQt5 shims. Note that shims don't "
        f"provide full support. {utils.MIGRATION_MSG}"
    )

# pylint: disable=wrong-import-position
from . import sip, Qt, QtCore, QtGui, QtWidgets  # noqa

print("#" * 70)
print(f"""# Please note that IDA is now using Qt 6, and PyQt5
# support will be dropped eventually.
# It is recommended to port your scripts/plugins to PySide6
# as soon as possible.
# Essentially, that means rewriting statement such as:
#
#   import PyQt5
#   import PyQt5.QtWidgets
#   from PyQt5.QtGui import QGuiApplication
#
# into:
#
#   import PySide6
#   import PySide6.QtWidgets
#   from PySide6.QtGui import QGuiApplication
#
# {utils.MIGRATION_MSG}""")
print("#" * 70)


__all__ = ["sip", "Qt", "QtCore", "QtGui", "QtWidgets"]
