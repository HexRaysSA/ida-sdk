"""
summary: query the UEFI analysis results from IDAPython

description:
  This script shows how to use uefi_svc_t, the public service of IDA's
  UEFI analysis, to query the modules of a firmware image, the protocol
  events found in them, the installed interfaces, the structure bound
  to a protocol, the functions implementing a protocol member and the
  calls through it, and the GUID database.

  Run `help(svc)` after `svc = ida_uefi.get_uefi_svc()` to see every
  method available.

  Run this script in a database of a UEFI module (a PE/TE image), or of
  a firmware image loaded by the UEFI firmware loader, once the
  autoanalysis has finished.

level: beginner
"""

import ida_uefi
import ida_name

svc = ida_uefi.get_uefi_svc()
if svc is None:
    print("Not a UEFI database; nothing to do.")
else:
    # 1. Modules: a firmware image has one per loaded PE/TE image, a
    # database of a single image has exactly one.
    print(f"Analyzed: {svc.is_analyzed()}")
    modules = svc.get_modules()
    print(f"{len(modules)} module(s):")
    for i, m in enumerate(modules):
        print(f"  #{i} {m.name} [{m.kind}] {m.start:x}-{m.end:x}"
              f" entry {m.entry:x}")

    # 2. Protocol events: installations, uninstallations, locates and
    # notification registrations, with the GUIDs involved. Later
    # versions may add kinds of events: do not assume the list below is
    # complete.
    kinds = {
        ida_uefi.UEFI_PK_INSTALL: "install",
        ida_uefi.UEFI_PK_UNINSTALL: "uninstall",
        ida_uefi.UEFI_PK_LOCATE: "locate",
        ida_uefi.UEFI_PK_NOTIFY: "notify",
    }
    protocols = svc.get_protocols()
    print(f"\n{len(protocols)} protocol event(s), the installations:")
    for p in protocols:
        if p.kind != ida_uefi.UEFI_PK_INSTALL:
            continue
        module = modules[p.module].name if p.module >= 0 else "?"
        guid = p.guid if p.guid_state == ida_uefi.UEFI_GS_KNOWN else "?"
        kind = kinds.get(p.kind, f"kind {p.kind}")
        print(f"  {p.call_ea:x} [{module}] {kind}"
              f" {p.name or guid} via {p.service}")

    # 3. The installed interfaces, and for the first protocol interface
    # (the others are service tables), the structure bound to its GUID,
    # the functions implementing its first member and the calls through
    # that member, across all modules.
    interfaces = svc.get_interfaces()
    print(f"\n{len(interfaces)} installed interface(s)")
    protocol_ifaces = [i for i in interfaces if not i.guid.empty()]
    if len(protocol_ifaces) > 0:
        iface = protocol_ifaces[0]
        print(f"  {iface.struct_name} at {iface.ea:x}"
              f" (synthesized: {iface.is_synthesized()})")
        print(f"    protocol {iface.guid} is bound to"
              f" {svc.get_protocol_struct(iface.guid)}")
        offset = 0
        for impl in svc.get_member_impls(iface.struct_name, offset):
            print(f"    member +{offset:x} implemented by"
                  f" {ida_name.get_name(impl.func)}")
        for call_ea in svc.get_member_calls(iface.struct_name, offset):
            print(f"    called at {call_ea:x}")

    # 4. The GUID database: names to GUIDs and back.
    guid = svc.find_guid("EfiDriverBindingProtocolGuid")
    print(f"\nEfiDriverBindingProtocolGuid = {guid}")
    if guid is not None:
        print(f"  {guid} is named {svc.get_guid_name(guid)}")
