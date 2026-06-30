"""
summary: extract embedded addresses from a tagged line

description:
  Clickable addresses are encoded inline as a `COLOR_ADDR` mark
  (`COLOR_ON` + `COLOR_ADDR` + 16 hex digits). Tagged lines come
  from `ida_lines.generate_disasm_line`, custom-viewer text, hint
  providers, or any string built with `ida_lines.tag_addr`.

  This example builds such a line and recovers the embedded ea_t
  via `tagged_line_section_t.get_addr`.

level: intermediate
"""

import ida_kernwin
import ida_lines


def main():
    # Build a tagged line carrying two clickable addresses.
    line = ("see "
            + ida_lines.tag_addr(0x401000) + "f1, "
            + ida_lines.tag_addr(0x402000) + "f2")

    # Parse the tagged sections and decode every COLOR_ADDR mark.
    tls = ida_kernwin.tagged_line_sections_t()
    ida_kernwin.parse_tagged_line_sections(tls, line)
    for sec in tls:
        if sec.tag == ida_lines.COLOR_ADDR:
            print(f"clickable address: {sec.get_addr(line):#x}")


if __name__ == '__main__':
    main()
