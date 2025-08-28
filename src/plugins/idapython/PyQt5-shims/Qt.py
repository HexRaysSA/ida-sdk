"""
This module exists for backward compatibility. It consolidates the contents of
three other modules (QtCore, QtGui and QtWidget) in the same namespace,
allowing legacy code to continue functioning without modification.
"""
# pylint: disable=wildcard-import,unused-wildcard-import
from .QtCore import *  # noqa
from .QtGui import *  # noqa
from .QtWidgets import *  # noqa

from . import QtCore, QtGui, QtWidgets


__qt_core_dir = dir(QtCore)
__qt_gui_dir = dir(QtGui)
__qt_widgets_dir = dir(QtWidgets)
__all_dir__ = __qt_core_dir + __qt_gui_dir + __qt_widgets_dir


def __dir__():  # Make dir() compatible
    return __all_dir__
