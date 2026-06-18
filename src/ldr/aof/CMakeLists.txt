# Loader: aof. unlib.cpp is a standalone librarian utility (has its own
# main()) shipped alongside, not part of the loader build.
ida_add_loader(aof
    SOURCES
        aof.cpp
        ../idaldr.h
        aof.h
)
