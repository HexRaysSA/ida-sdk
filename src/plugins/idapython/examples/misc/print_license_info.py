"""
summary: print the active license and what it covers

description:
  The License class from the ida_license module reports the license
  IDA is running with: its id, product and edition, whether it is
  usable, when its activation period ends, and the add-ons and
  features it covers.

  The example also checks whether the HEXX64 add-on (the x64
  decompiler) is usable.

level: beginner
"""

import datetime

import ida_license

lic = ida_license.License()
if not lic.id:
    print("No active license")
else:
    print(f"License {lic.id}: {lic.product} ({lic.edition})")
    print(lic.description)
    print(f"Usable: {lic.valid}")

    if lic.end:
        print(f"Activation period ends: {datetime.date.fromtimestamp(lic.end)}")
    else:
        print("Activation period: no expiry")

    for code in lic.add_ons:
        print(f"Usable add-on: {code}")
    for name in lic.features:
        print(f"Feature: {name}")

    if lic.has_add_on("HEXX64"):
        print("The HEXX64 add-on is usable")
    else:
        print("The HEXX64 add-on is not usable")
