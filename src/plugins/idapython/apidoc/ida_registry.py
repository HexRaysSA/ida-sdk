
def reg_read_strlist(subkey: str) -> List[str]:
    """
    Retrieve all string values associated with the given key.

    :param subkey: a key from which to read the list of items
    :returns: the list of items
    """
    pass


def reg_write_strlist(items: List[str], subkey: str):
    """
    Write string values associated with the given key.

    :param items: the list of items to write
    :param subkey: a key under which to write the list of items
    """
    pass


def reg_update_strlist(subkey: str, add: Union[str, None], maxrecs: int, rem: Union[str, None]=None, ignorecase: bool=False):
    """
    Add and/or remove items from the list, and possibly trim that list.

    :param subkey: the key under which the list is located
    :param add: an item to add to the list, or None
    :param maxrecs: the maximum number of items the list should hold
    :param rem: an item to remove from the list, or None
    :param ignorecase: ignore case for 'add' and 'rem'
    """
    pass
