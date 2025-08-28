"""Proxy for PySide6.QtWidgets"""
import PySide6.QtWidgets as _pyside6_qtwidgets
from PySide6.QtGui import QAction as _PySide6_QAction

from .utils import _clone_module

_clone_module(globals(), _pyside6_qtwidgets)

QAction = _PySide6_QAction
