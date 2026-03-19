"""Functions that deal with the list of problems.

There are several problem lists. An address may be inserted to any list. The kernel simply maintains these lists, no additional processing is done.
The problem lists are accessible for the user from the View->Subviews->Problems menu item.
Addresses in the lists are kept sorted. In general IDA just maintains these lists without using them during analysis (except PR_ROLLED). 
"""
