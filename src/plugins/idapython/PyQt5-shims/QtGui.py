"""Proxy for PySide6.QtGui"""
import PySide6.QtGui as _pyside6_qtgui

from .utils import _clone_module

_clone_module(globals(), _pyside6_qtgui)


class QFontDatabase(_pyside6_qtgui.QFontDatabase):
    """
    Shim for PySide6.QtCore.QFontDatabase that provides compatibility for
    legacy code transitioning from PyQt5 to PySide6.

    This class wraps PySide6's QFontDatabase to support methods and attributes
    available in PyQt5
    """
    def __init__(self):
        super().__init__()

        for enum in (self.__class__.SystemFont, self.__class__.WritingSystem):
            for font in enum:
                setattr(self, font.name, font)
