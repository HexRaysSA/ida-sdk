"""Functions that provide the lowest level public interface to the database. Namely, we use Btree. To learn more about BTree:

[https://en.wikipedia.org/wiki/B-tree](https://en.wikipedia.org/wiki/B-tree)
We do not use Btree directly. Instead, we have another layer built on the top of Btree. Here is a brief explanation of this layer.
An object called "netnode" is modeled on the top of Btree. Each netnode has a unique id: a 32-bit value (64-bit for ida64). Initially there is a trivial mapping of the linear addresses used in the program to netnodes (later this mapping may be modified using ea2node and node2ea functions; this is used for fast database rebasings). If we have additional information about an address (for example, a comment is attached to it), this information is stored in the corresponding netnode. See nalt.hpp to see how the kernel uses netnodes. Also, some netnodes have no corresponding linear address (however, they still have an id). They are used to store information not related to a particular address.
Each netnode _may_ have the following attributes:

* a name: an arbitrary non-empty string, up to 255KB-1 bytes
* a value: arbitrary sized object, max size is MAXSPECSIZE
* altvals: a sparse array of 32-bit values. indexes in this array may be 8-bit or 32-bit values
* supvals: an array of arbitrary sized objects. (size of each object is limited by MAXSPECSIZE) indexes in this array may be 8-bit or 32-bit values
* charvals: a sparse array of 8-bit values. indexes in this array may be 8-bit or 32-bit values
* hashvals: a hash (an associative array). indexes in this array are strings values are arbitrary sized (max size is MAXSPECSIZE)


Initially a new netnode contains no information at all so no disk space is used for it. As you add new information, the netnode grows.
All arrays that are attached to the netnode behave in the same manner. Initially:
* all members of altvals/charvals array are zeroes
* all members of supvals/hashvals array are undefined


If you need to store objects bigger that MAXSPECSIZE, please note that there are high-level functions to store arbitrary sized objects in supvals. See setblob/getblob and other blob-related functions.
You may use netnodes to store additional information about the program. Limitations on the use of netnodes are the following:

* use netnodes only if you could not find a kernel service to store your type of information
* do not create netnodes with valid identifier names. Use the "$ " prefix (or any other prefix with characters not allowed in the identifiers for the names of your netnodes. Although you will probably not destroy anything by accident, using already defined names for the names of your netnodes is still discouraged.
* you may create as many netnodes as you want (creation of an unnamed netnode does not increase the size of the database). however, since each netnode has a number, creating too many netnodes could lead to the exhaustion of the netnode numbers (the numbering starts at 0xFF000000)
* remember that netnodes are automatically saved to the disk by the kernel.


Advanced info:
In fact a netnode may contain up to 256 arrays of arbitrary sized objects (not only the 4 listed above). Each array has an 8-bit tag. Usually tags are represented by character constants. For example, altvals and supvals are simply 2 of 256 arrays, with the tags 'A' and 'S' respectively. 
"""

class netnode(object):
    def getblob(self, start, tag) -> Union[bytes, None]:
        """
        Get a blob from a netnode.

        :param start: the index where the blob starts (it may span on multiple indexes)
        :param tag: the netnode tag
        :returns: a blob, or None
        """
        pass

    def getclob(self, start, tag) -> Union[str, None]:
        """
        Get a large amount of text from a netnode.

        :param start: the index where the clob starts (it may span on multiple indexes)
        :param tag: the netnode tag
        :returns: a clob, or None
        """
        pass

