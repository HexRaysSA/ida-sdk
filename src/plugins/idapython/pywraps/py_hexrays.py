"""This is python wrapper code that will be inserted into final
ida_hexrays.py"""
#<pycode(py_hexrays)>
import ida_pro
import ida_range

from ida_hexrays_defs import *
from ida_hexrays_micro import *
from ida_hexrays_ctree import *

def _map_as_dict(_ida_module, maptype, name, keytype, valuetype):

    maptype.keytype = keytype
    maptype.valuetype = valuetype

    for fctname in ['begin', 'end', 'first', 'second', 'next', \
                        'find', 'insert', 'erase', 'clear', 'size']:
        fct = getattr(_ida_module, name + '_' + fctname)
        setattr(maptype, '__' + fctname, fct)

    maptype.__len__ = maptype.size
    maptype.__getitem__ = maptype.at

    maptype.begin = lambda self, *args: self.__begin(self, *args)
    maptype.end = lambda self, *args: self.__end(self, *args)
    maptype.first = lambda self, *args: self.__first(*args)
    maptype.second = lambda self, *args: self.__second(*args)
    maptype.next = lambda self, *args: self.__next(*args)
    maptype.find = lambda self, *args: self.__find(self, *args)
    maptype.insert = lambda self, *args: self.__insert(self, *args)
    maptype.erase = lambda self, *args: self.__erase(self, *args)
    maptype.clear = lambda self, *args: self.__clear(self, *args)
    maptype.size = lambda self, *args: self.__size(self, *args)

    def _map___iter__(self):
        """ Iterate over dictionary keys. """
        return self.iterkeys()
    maptype.__iter__ = _map___iter__

    def _map___getitem__(self, key):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of key should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        return self.second(self.find(key))
    maptype.__getitem__ = _map___getitem__

    def _map___setitem__(self, key, value):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if not isinstance(value, self.valuetype):
            raise KeyError('type of `value` should be ' + repr(self.valuetype) + ' but got ' + type(value))
        self.insert(key, value)
        return
    maptype.__setitem__ = _map___setitem__

    def _map___delitem__(self, key):
        """ Removes the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        self.erase(self.find(key))
        return
    maptype.__delitem__ = _map___delitem__

    def _map___contains__(self, key):
        """ Returns true if the specified key exists in the . """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if self.find(key) != self.end():
            return True
        return False
    maptype.__contains__ = _map___contains__

    def _map_clear(self):
        self.clear()
        return
    maptype.clear = _map_clear

    def _map_copy(self):
        ret = {}
        for k in self.iterkeys():
            ret[k] = self[k]
        return ret
    maptype.copy = _map_copy

    def _map_get(self, key, default=None):
        if key in self:
            return self[key]
        return default
    maptype.get = _map_get

    def _map_iterkeys(self):
        iter = self.begin()
        while iter != self.end():
            yield self.first(iter)
            iter = self.next(iter)
        return
    maptype.iterkeys = _map_iterkeys

    def _map_itervalues(self):
        iter = self.begin()
        while iter != self.end():
            yield self.second(iter)
            iter = self.next(iter)
        return
    maptype.itervalues = _map_itervalues

    def _map_iteritems(self):
        iter = self.begin()
        while iter != self.end():
            yield (self.first(iter), self.second(iter))
            iter = self.next(iter)
        return
    maptype.iteritems = _map_iteritems

    def _map_keys(self):
        return list(self.iterkeys())
    maptype.keys = _map_keys

    def _map_values(self):
        return list(self.itervalues())
    maptype.values = _map_values

    def _map_items(self):
        return list(self.iteritems())
    maptype.items = _map_items

    def _map_has_key(self, key):
        return key in self
    maptype.has_key = _map_has_key

    def _map_pop(self, key):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        ret = self[key]
        del self[key]
        return ret
    maptype.pop = _map_pop

    def _map_popitem(self):
        """ Sets the value associated with the provided key. """
        if len(self) == 0:
            raise KeyError('key not found')
        key = self.keys()[0]
        return (key, self.pop(key))
    maptype.popitem = _map_popitem

    def _map_setdefault(self, key, default=None):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key in self:
            return self[key]
        self[key] = default
        return default
    maptype.setdefault = _map_setdefault

_map_as_dict(_ida_hexrays, user_numforms_t, 'user_numforms', operand_locator_t, number_format_t)
_map_as_dict(_ida_hexrays, user_cmts_t, 'user_cmts', treeloc_t, citem_cmt_t)
_map_as_dict(_ida_hexrays, user_iflags_t, 'user_iflags', citem_locator_t, int)
_map_as_dict(_ida_hexrays, user_unions_t, 'user_unions', ida_idaapi.integer_types, ida_pro.intvec_t)
_map_as_dict(_ida_hexrays, eamap_t, 'eamap', ida_idaapi.long_type, cinsnptrvec_t)
_map_as_dict(_ida_hexrays, boundaries_t, 'boundaries', cinsn_t, ida_range.rangeset_t)
#</pycode(py_hexrays)>
