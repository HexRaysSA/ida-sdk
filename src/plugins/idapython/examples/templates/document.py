"""
Produce-HTML template: a standalone HTML document of a listing view.

IDA's colors as a stylesheet, clickable cross-reference / name links, and the
rows chunked so a large document loads fast.

See README.md for the template contract.
"""
import ida_lines

title = "Plain static export"
description = ("A standalone HTML page of the listing, with IDA's colors in a "
               "stylesheet and clickable cross-reference / name links.")

_ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}


def _esc(s):
    return "".join(_ESC.get(c, c) for c in s)


def _basename(path):
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def run(out_path, cfg):
    # one generator per range (an empty line separates the regions); the
    # generators of one pass share the document's links/anchors
    gens = [cfg.create_lines(ida_lines.LLFMT_HTML_CLASSES | ida_lines.LLF_LINKS,
                             ri)
            for ri in range(len(cfg.ranges))]
    style = (gens[0].get_style_block() if gens else "") or ""
    doc_title = cfg.title or _basename(out_path)
    # rows go out in <pre class="ck"> chunks; content-visibility skips off-screen
    # ones. --n is the chunk's line count, so the reserved height is exact.
    CHUNK = 500
    with open(out_path, "w", encoding="utf-8") as fh:
        # font-family comes from the template (the view's reads poorly in a
        # browser); edit to taste.
        fh.write("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
                 "<title>%s</title>\n<style>\n"
                 ".ida-listing { font: 13px/1.2 ui-monospace, 'SFMono-Regular',"
                 " Menlo, Consolas, 'Liberation Mono', monospace; }\n"
                 ".ck { margin: 0; content-visibility: auto;\n"
                 "  contain-intrinsic-size: auto calc(var(--n) * 1.2em);\n"
                 "  contain-intrinsic-size: auto calc(var(--n) * 1lh); }\n"
                 "%s</style>\n</head>\n<body>\n" % (_esc(doc_title), style))
        buf = []

        def _flush():
            if buf:
                fh.write('<pre class="ck ida-listing" style="--n:%d">%s\n</pre>'
                         % (len(buf), "\n".join(buf)))
                del buf[:]

        # next() ends the stream on cancel; the C++ side drops the partial file.
        for ri, gen in enumerate(gens):
            if ri:
                buf.append("")
            while True:
                ln = gen.next()
                if ln is None:
                    break
                buf.append(ln.text)
                if len(buf) >= CHUNK:
                    _flush()
            if gen.was_cancelled():
                return
        _flush()
        fh.write("\n</body>\n</html>\n")
