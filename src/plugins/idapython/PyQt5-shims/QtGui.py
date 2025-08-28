"""Proxy for PySide6.QtGui"""
import PySide6.QtGui as _pyside6_qtgui

from .utils import _clone_module

_clone_module(globals(), _pyside6_qtgui)
