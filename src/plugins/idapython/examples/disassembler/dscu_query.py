"""
summary: query a Dyld Shared Cache (DSC) from IDAPython

description:
  This script touches a few highlights of dscu_svc_t -- the public
  service driving IDA's DSC workflow: cache layout, image lookup,
  symbol search, string search.

  The full surface is much wider than what's shown here -- it can
  also load modules on demand, walk dependencies, query regions, etc.
  Run `help(svc)` after `svc = ida_dscu.get_dscu_svc()` to see every
  method available.

  Run this script in a database opened from a DSC file.

level: beginner
"""

import os
import ida_dscu

svc = ida_dscu.get_dscu_svc()
if svc is None:
    print("Not a Dyld Shared Cache database; nothing to do.")
else:
    # 1. Cache layout.
    _, cache_basename = os.path.split(svc.get_input_file_path())
    print(f"Cache: {cache_basename}")
    print(f"Number of images: {len(svc.get_images_names())}")
    print(f"Dyld slide: {svc.get_dyld_slide():#x}")

    # 2. Image lookup -- find an image by name, print its layout
    # info, then list its immediate dependencies (the libraries it
    # links against).
    image_name = "/usr/lib/system/libsystem_malloc.dylib"
    idx = svc.get_image_index(image_name)
    if idx >= 0:
        print(f"\n{image_name}:")
        print(f"  image_index = {idx}")
        print(f"  base ea = {svc.get_image_address(idx):x}")
        print(f"  loaded  = {svc.is_image_loaded(idx)}")
        print("  depends on:")
        for dep in svc.get_image_dependencies(idx):
            print(f"    {svc.get_image_name(dep)}")

    # 3. Symbol search across the cache. `max_count` caps the result
    # vector, useful when you only want a few hits.
    print("\nFirst 3 symbol matches for 'Block':")
    for m in svc.find_symbol("Block", 0, 3):
        print(f"  {m.ea:x} {m.symbol} (image #{m.image_index})")

    # 4. String search across the cache.
    print("\nFirst 3 string matches for 'malloc_zone':")
    for m in svc.find_string("malloc_zone", 0, 3):
        print(f"  {m.ea:x} [{m.context}]")

    # 5. Cache-wide data regions (e.g. linkedit subcache mappings) are
    # surfaced as `rt_cache_data` umbrellas and can be loaded into the
    # database with `load_cache_data()`.
    regions = svc.get_regions()
    cache_data = [r for r in regions if r.type == ida_dscu.rt_cache_data]
    print(f"\nCache data umbrellas: {len(cache_data)}")
    if cache_data:
        ri = cache_data[0]
        print(f"  first: {ri.name} @ {ri.start:x} (size {ri.size:#x})")
        print(f"  loaded before: {svc.is_cache_data_loaded(ri.start)}")
        svc.load_cache_data(ri.start)
        print(f"  loaded after:  {svc.is_cache_data_loaded(ri.start)}")
