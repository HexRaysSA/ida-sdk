"""
Produce-HTML template: a self-contained HTML snippet of a listing view.

Like document.py, but an inline-styled <pre> with inline colors and no <style>
block -- paste-ready into an existing document.

See README.md for the template contract.
"""
import ida_lines

title = "Snippet"
description = ("A paste-ready HTML fragment: an inline-styled block with "
               "per-span colors and no stylesheet, to drop into a document.")

_PRE_STYLE = "white-space: pre; font-family: monospace;"


def run(out_path, cfg):
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write('<pre style="%s">\n' % _PRE_STYLE)
        # one generator per range, an empty line between the regions
        for ri in range(len(cfg.ranges)):
            if ri:
                fh.write("\n")
            gen = cfg.create_lines(ida_lines.LLFMT_HTML_INLINE, ri)
            # next() ends the stream on cancel; the C++ side drops the file.
            while True:
                ln = gen.next()
                if ln is None:
                    break
                fh.write(ln.text)
                fh.write("\n")
            if gen.was_cancelled():
                return
        fh.write("</pre>\n")
