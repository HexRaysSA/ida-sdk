"""Proxy for PySide6.QtCore with few PyQt5 compatible classes"""
# pylint: disable=invalid-name; CamelCase came from Qt
import enum
import warnings

import PySide6.QtCore as _pyside6_qtcore

from .utils import _clone_module

_clone_module(globals(), _pyside6_qtcore)


# All the rest for partial PyQt5 compatibility
pyqtSignal = _pyside6_qtcore.Signal
pyqtSlot = _pyside6_qtcore.Slot
_recommendation = "It is recommended to port your scripts/plugins to PySide6" \
    " as soon as possible"


class QObject(_pyside6_qtcore.QObject):
    """
    Some plugins (e.g., Lucid microcode explorer) use an incorrect syntax
    to perform method resolution:

        class FilterMenu(QtCore.QObject):
            def __init__(self, qmenu):
                super(QtCore.QObject, self).__init__()
                self.qmenu = qmenu

    (The proper syntax would be to call `super(FilterMenu, self)`).

    While incorrect, that code used to work with PyQt5, due to method resolution & the PyQt5 type hierarchy.
    To support such constructs, we provide this (empty) PyQt5.QtCore.QObject indirection.
    """
    pass

# pylint: disable=too-few-public-methods; Inheritance and compatibility
class QProcess(_pyside6_qtcore.QProcess):
    """PySide6.QtCore.QProcess with overridden error property for compatibility
    """
    error = _pyside6_qtcore.QProcess.errorOccurred


class QMutex:
    """
    Shim for PySide6.QtCore.QMutex that provides compatibility for legacy code
    transitioning from PyQt5 to PySide6.

    This class wraps PySide6's QMutex and QRecursiveMutex to support
    initialization using recursion mode and implements the deprecated
    `isRecursive()` method. This shim is temporary and will be removed
    in future releases.
    """

    class RecursionMode(enum.IntEnum):
        """
        Enumeration for recursion mode to mimic Qt4/Qt5 behavior.

        Attributes:
            Recursive (int): Indicates a recursive mutex (value 1).
            NonRecursive (int): Indicates a non-recursive mutex (value 0).
        """
        Recursive = 1
        NonRecursive = 0

    Recursive = RecursionMode.Recursive
    NonRecursive = RecursionMode.NonRecursive

    def __init__(self, mode: "QMutex.RecursionMode" = None):
        """
        Initialize the QMutex shim.

        Args:
            mode (QMutex.RecursionMode, optional): Determines whether a
                recursive or non-recursive mutex is used. This is provided for
                compatibility and will be ignored in future Qt6 versions.
        """
        if mode is not None:
            warnings.warn(
                "QMutex no longer accepts a recursion mode in Qt6. "
                + _recommendation, FutureWarning
            )
        if mode:  # Recursive
            self._impl = _pyside6_qtcore.QRecursiveMutex()
        else:
            self._impl = _pyside6_qtcore.QMutex()

    def isRecursive(self) -> bool:
        """
        Determine if the underlying mutex is recursive.

        Returns:
            bool: True if using QRecursiveMutex; otherwise, False.
        """
        warnings.warn(
            f"QMutex.isRecursive() is retired in Qt6 and is only available "
            f"in this shim. {_recommendation}", FutureWarning
        )
        return isinstance(self._impl, _pyside6_qtcore.QRecursiveMutex)

    def tryLock(self, timeout: int = 0) -> bool:
        """tryLock shim with allowed keyword argument for PyQt5 compatibility
        """
        return self._impl.tryLock(timeout)  # Qt6 QMutex doesn't support kwargs

    def __getattr__(self, name):
        """
        Delegate attribute access to the underlying mutex implementation.

        This method is called when the requested attribute is not found in this
        shim, allowing passthrough to the internal QMutex or QRecursiveMutex
        instance.

        Args:
            name (str): The attribute name.

        Returns:
            Any: The attribute value from the underlying mutex object.
        """
        return getattr(self._impl, name)


QT_VERSION_STR = _pyside6_qtcore.__version__
# QT_VERSION expanded a numeric value of the form 0xMMNNPP
# (MM = major, NN = minor, PP = patch) that specifies Qt’s version number.
# For example, if you compile your application against Qt 4.1.2, the macro
# expanded to 0x040102.
QT_VERSION: int = (
    _pyside6_qtcore.__version_info__[0] << 16
    | _pyside6_qtcore.__version_info__[1] << 8
    | _pyside6_qtcore.__version_info__[2]
)

PYQT_VERSION_STR = "5.15.6"  # This is shim for PyQt5 5.15.6
PYQT_VERSION: int = 0x50f06
