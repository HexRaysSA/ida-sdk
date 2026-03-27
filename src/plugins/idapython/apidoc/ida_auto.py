"""Functions that work with the autoanalyzer queue.

The autoanalyzer works when IDA is not busy processing the user keystrokes.
It has several queues, each queue having its own priority. The analyzer stops
when all queues are empty.

A queue contains addresses or address ranges. The addresses are kept sorted by
their values. The analyzer will process all addresses from the first queue,
then switch to the second queue and so on. There are no limitations on the
size of the queues.

This file also contains functions that deal with the IDA status indicator and
the autoanalysis indicator. You may use these functions to change the
indicator value.

.. tip::
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies
   common tasks and provides better type hints, while remaining fully compatible
   with IDAPython for advanced use cases.

   For auto-analysis operations, see :mod:`ida_domain.database`."""
