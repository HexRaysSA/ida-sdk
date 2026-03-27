"""Architecture independent exception handling info.

Try blocks have the following general properties:
* A try block specifies a possibly fragmented guarded code region.
* Each try block has always at least one catch/except block description
* Each catch block contains its boundaries and a filter.
* Additionally a catch block can hold sp adjustment and the offset to the exception object offset (C++).
* Try blocks can be nested. Nesting is automatically calculated at the retrieval time.
* There may be (nested) multiple try blocks starting at the same address.


See examples in tests/input/eh_tests.
"""
