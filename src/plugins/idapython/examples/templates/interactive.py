"""
Produce-HTML template: an interactive, self-contained page of a listing view.

Draws a jump-arrow gutter over the listing, pairing each line's link-graph
endpoints (listing_line_t.anchors) into edges. Everything is embedded: no
external CSS/JS/fonts.

See README.md for the template contract.
"""
import json
import re
import ida_lines
import ida_nalt
import ida_idaapi
import ida_funcs
import ida_name

title = "Interactive with sidebar"
description = ("A standalone HTML page featuring a list of exported functions, "
               "a live jump-arrow gutter, and toggles for prefixes, "
               "cross-references, comments and arrows.")


_ESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}


def _esc(s):
    return "".join(_ESC.get(c, c) for c in s)


def _basename(path):
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _anchor_name(ident):
    # the inverse of the exporter's anchor-id encoding: strip the "sym-"
    # prefix, decode the %XX escapes
    return re.sub(r"%([0-9A-Fa-f]{2})",
                  lambda m: chr(int(m.group(1), 16)), ident[4:])


def _ida_listing_css_value(style, prop):
    # pull one property from the ".ida-listing { ... }" rule ("color" must not
    # match inside "background-color", hence the ^|; anchor)
    body = re.search(r"\.ida-listing\s*\{([^}]*)\}", style)
    if body is None:
        return None
    val = re.search(r"(?:^|;)\s*%s:\s*([^;]+)" % re.escape(prop), body.group(1))
    return val.group(1).strip() if val is not None else None


# unchecking a toolbar box adds the matching body class
_TOGGLE_JS = """
(function(){
  function bind(id,cls){
    var el=document.getElementById(id);
    if(el)el.addEventListener('change',function(){
      document.body.classList.toggle(cls,!el.checked);
    });
  }
  bind('t-pfx','hide-prefix');
  bind('t-xr','hide-xrefs');
  bind('t-cm','hide-comments');
  bind('t-ar','hide-arrows');
  bind('t-fl','hide-fnlist');
})();
"""


# layout only; colours come from IDA's palette (style block + --bg/--fg)
_CSS = """
:root {
  /* sidebar width */
  --fnlist-w: clamp(160px, 20vw, 300px);
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  padding-top: 34px;
  background: var(--bg);
  color: var(--fg);
  font: 13px/1.5 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
}

/* pinned control panel */
.tb {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 10;
  height: 34px;
  display: flex;
  gap: 16px;
  align-items: center;
  padding: 0 12px;
  font-size: 12px;
  background: var(--bg);
  border-bottom: 1px solid rgba(128, 128, 128, .35);
}
.tb label {
  cursor: pointer;
  user-select: none;
}

.meta {
  padding: 8px 12px;
  opacity: .7;
  border-bottom: 1px solid rgba(128, 128, 128, .35);
  white-space: nowrap;
  overflow-x: auto;
}
.meta b {
  opacity: 1;
  font-weight: 600;
}

/* function sidebar (disassembly only) */
.fnlist {
  position: fixed;
  left: 0;
  top: 34px;
  bottom: 0;
  width: var(--fnlist-w);
  overflow: auto;
  z-index: 6;
  padding: 6px 4px;
  font-size: 12px;
  background: var(--bg);
  border-right: 1px solid rgba(128, 128, 128, .35);
}
.fnlist a {
  display: block;
  color: var(--fg);
  text-decoration: none;
  padding: 1px 6px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  opacity: .85;
}
.fnlist a:hover {
  background: rgba(128, 128, 128, .18);
  opacity: 1;
}
body.has-fnlist .meta,
body.has-fnlist .code-wrap {
  margin-left: var(--fnlist-w);
}
body.hide-fnlist .fnlist {
  display: none;
}
body.hide-fnlist .meta,
body.hide-fnlist .code-wrap {
  margin-left: 0;
}

/* toggles hide runs by exact semantic class (a hash lookup, not a [class*=] scan) */
body.hide-xrefs .line-fg-code-xref,
body.hide-xrefs .line-fg-data-xref {
  display: none;
}
body.hide-comments .line-fg-regular-comment,
body.hide-comments .line-fg-automatic-comment,
body.hide-comments .line-fg-repeatable-comment {
  display: none;
}
body.hide-prefix .line-pfx-libfunc,
body.hide-prefix .line-pfx-func,
body.hide-prefix .line-pfx-insn,
body.hide-prefix .line-pfx-data,
body.hide-prefix .line-pfx-unexplored,
body.hide-prefix .line-pfx-extern,
body.hide-prefix .line-pfx-current-item,
body.hide-prefix .line-pfx-current-line,
body.hide-prefix .line-pfx-hidden-line,
body.hide-prefix .line-pfx-lumina {
  display: none;
}
body.hide-arrows svg.agut {
  display: none;
}
body.hide-arrows .code-wrap {
  padding-left: 0;
}

/* rows keep 'pre'; the wrapper collapses the newlines between row <div>s */
.code-wrap {
  position: relative;
  padding-left: var(--gutter);
  line-height: 1.2;
  white-space: normal;
}

svg.agut {
  position: absolute;
  left: 0;
  top: 0;
  width: var(--gutter);
  height: 100%;
  background: rgba(128, 128, 128, .10);
  z-index: 2;
}
svg.agut .hit {
  fill: none;
  stroke: transparent;
  stroke-width: 11;
  cursor: pointer;
}
svg.agut .vis {
  fill: none;
  stroke-width: 1.4;
  opacity: .75;
  transition: stroke-width .08s ease, opacity .08s ease;
}
svg.agut .vis.down {
  stroke: var(--arrow);
}
svg.agut .vis.up {
  stroke: var(--arrow-up);
}
svg.agut .edge:hover .vis {
  stroke-width: 3.4;
  opacity: 1;
}

/* every row is exactly 1lh tall, so the gutter places arrows by arithmetic */
.row {
  white-space: pre;
  padding: 0 12px;
  height: 1.2em;
  height: 1lh;
  overflow: hidden;
}

/* content-visibility skips off-screen chunks; --n = exact row count */
.ck {
  content-visibility: auto;
  contain-intrinsic-size: auto calc(var(--n) * 1.2em);
  contain-intrinsic-size: auto calc(var(--n) * 1lh);
}

/* keep anchor jumps clear of the fixed control panel */
.code-wrap [id] {
  scroll-margin-top: 44px;
}
/* highlight the row holding the :target anchor */
.row:has(:target) {
  background: rgba(128, 128, 128, .28);
}
.row a {
  color: inherit;
  text-decoration: none;
  border-bottom: 1px dotted rgba(128, 128, 128, .6);
}
.row a:hover {
  border-bottom-style: solid;
}
"""

_JS = """
(function(){
  var svg=document.getElementById('agut');
  var wrap=document.getElementById('cw');
  if(!svg||!wrap||!window.EDGES)return;
  var SVGNS='http://www.w3.org/2000/svg';
  var GROUPS=EDGES;              // per function: [minRow, maxRow, [[src,dst],...]]
  var MARGIN=1000;              // build functions within this many px of the view
  var minDepart=24, step=9;     // fixed lane step
  var wrapTop=0;
  var W=72;                     // gutter width
  var rowH=0, rowY0=0;          // fixed row height / first row offset
  var spans=[];                 // per group {top,bot}
  var geo=[];                   // per group: lazily lane-packed (cached)
  var nodes={};                 // group index -> <g> in the DOM

  function markerDefs(){
    var cs=getComputedStyle(document.documentElement);
    function mk(id,c){
      return '<marker id="'+id+'" viewBox="0 0 10 10" refX="8" refY="5"'
        +' markerWidth="6" markerHeight="6" orient="auto">'
        +'<path d="M0,0 L10,5 L0,10 z" fill="'+c+'"></path></marker>';
    }
    return '<defs>'
      +mk('ah-down',(cs.getPropertyValue('--arrow')||'#3b82f6').trim())
      +mk('ah-up',(cs.getPropertyValue('--arrow-up')||'#e08a3c').trim())
      +'</defs>';
  }
  // fixed-height rows: a row's center is pure arithmetic (no reflows)
  function cy(i){ return rowY0+i*rowH+rowH/2; }

  // measure once per layout: one rect for the wrap, one for the first row
  function measure(){
    var wr=wrap.getBoundingClientRect();
    wrapTop=wr.top+window.scrollY;
    var r0=wrap.querySelector('.row').getBoundingClientRect();
    rowH=r0.height;
    rowY0=r0.top-wr.top;
    W=parseFloat(getComputedStyle(document.documentElement)
      .getPropertyValue('--gutter'))||72;
    svg.setAttribute('height',wrap.scrollHeight);
    svg.innerHTML=markerDefs();
    nodes={}; geo=[];
    spans=GROUPS.map(function(g){ return {top:cy(g[0]),bot:cy(g[1])}; });
  }

  // lane-pack one function's arrows on first use; reuse after
  function build(gi){
    if(geo[gi])return geo[gi];
    var es=GROUPS[gi][2].map(function(e){
      var a=cy(e[0]),b=cy(e[1]);
      return {y0:a,y1:b,top:Math.min(a,b),bot:Math.max(a,b)};
    }).sort(function(p,q){return p.top-q.top});
    var laneBot=[];
    es.forEach(function(e){
      for(var l=0;l<laneBot.length;l++){
        if(e.top>=laneBot[l]){e.lane=l;laneBot[l]=e.bot;return;}
      }
      e.lane=laneBot.length; laneBot.push(e.bot);
    });
    return (geo[gi]=es.map(function(e){
      var x=W-minDepart-e.lane*step; if(x<4)x=4;
      return {d:'M'+(W-1)+','+e.y0+' H'+x+' V'+e.y1+' H'+(W-3),
              dir:e.y1<e.y0?'up':'down'};
    }));
  }
  function nodeFor(gi){
    var g=document.createElementNS(SVGNS,'g');
    build(gi).forEach(function(p){
      var e=document.createElementNS(SVGNS,'g'); e.setAttribute('class','edge');
      var hit=document.createElementNS(SVGNS,'path');
      hit.setAttribute('class','hit'); hit.setAttribute('d',p.d);
      var vis=document.createElementNS(SVGNS,'path');
      vis.setAttribute('class','vis '+p.dir); vis.setAttribute('d',p.d);
      vis.setAttribute('marker-end','url(#ah-'+p.dir+')');
      e.appendChild(hit); e.appendChild(vis); g.appendChild(e);
    });
    return g;
  }

  // draw only functions whose arrows overlap the viewport (+ margin)
  function render(){
    var vTop=window.scrollY-wrapTop-MARGIN;
    var vBot=window.scrollY+window.innerHeight-wrapTop+MARGIN;
    for(var i=0;i<spans.length;i++){
      var s=spans[i], vis=(s.bot>=vTop && s.top<=vBot);
      if(vis && !nodes[i]) nodes[i]=svg.appendChild(nodeFor(i));
      else if(!vis && nodes[i]){ svg.removeChild(nodes[i]); delete nodes[i]; }
    }
  }

  var raf;
  function onScroll(){ cancelAnimationFrame(raf); raf=requestAnimationFrame(render); }
  function onResize(){ cancelAnimationFrame(raf);
    raf=requestAnimationFrame(function(){ measure(); render(); }); }
  measure(); render();
  window.addEventListener('scroll',onScroll,{passive:true});
  window.addEventListener('resize',onResize);
})();
"""


def run(out_path, cfg):
    nranges = len(cfg.ranges)
    style = None
    doc_title = cfg.title or _basename(out_path)

    rows = []              # rendered HTML per row
    row_ea = []            # each row's effective address (BADADDR if none)
    defs = {}              # identifier -> row index of its definition
    out_edges = []         # (row index, identifier) of outgoing references
    lo = hi = None
    funcs = []             # (name, identifier) of the functions in the export
    fn_end = 0             # current function's end (query only past it)
    fn_pending = {}        # func-entry ea -> name, until we resolve its identifier
    fei = ida_funcs.func_entry_info_t()
    cancelled = False
    # one generator per range: the region boundaries are structural (an empty
    # line separates them), and each range says what it is -- its place kind,
    # and its subject for the by-place kinds (a decompiled function)
    for ri in range(nranges):
        gen = cfg.create_lines(
            ida_lines.LLFMT_HTML_CLASSES | ida_lines.LLF_LINKS, ri)
        if style is None:
            style = gen.get_style_block() or ""
        r = cfg.ranges[ri]
        kind = r.first.at.name() if r.first.at is not None else ""
        fn_ida = kind == "idaplace_t"
        # a by-place range's subject: the ea its places carry (a pseudocode
        # range: the decompiled function)
        subject = (r.first.at.toea()
                   if not fn_ida and r.first.at is not None
                   else ida_idaapi.BADADDR)
        subject_pending = subject != ida_idaapi.BADADDR
        if rows:
            rows.append("")
            row_ea.append(ida_idaapi.BADADDR)
        while True:
            ln = gen.next()
            if ln is None:
                break
            idx = len(rows)
            for a in ln.anchors:
                # xref endpoints (LAF_XREF) are already linked inline in the
                # text; drawing arrows for them too would clutter the gutter
                if a.flags & ida_lines.LAF_XREF:
                    continue
                if a.flags & ida_lines.LAF_INCOMING:
                    defs.setdefault(a.identifier, idx)
                if a.flags & ida_lines.LAF_OUTGOING:
                    out_edges.append((idx, a.identifier))
            ea = ln.place.toea() if ln.place is not None else ida_idaapi.BADADDR
            # function sidebar. Disassembly: resolve each entry's id at its
            # definition row, where place_to_identifier has seen the anchor.
            if fn_ida and ea != ida_idaapi.BADADDR:
                if ea >= fn_end:
                    if ida_funcs.get_func_entry_info(fei, ea,
                                                     ida_funcs.GFI_NAME):
                        fn_end = fei.end_ea
                        # sidebar label: the readable (demangled) name; the
                        # anchor id stays the unambiguous mangled name
                        fn_pending[fei.start_ea] = (
                            ida_name.get_short_name(fei.start_ea)
                            or fei.get_name())
                    else:
                        fn_end = ea + 1
                if ea in fn_pending:
                    ident = gen.place_to_identifier(ln.place)
                    if ident:
                        funcs.append((fn_pending.pop(ea), ident))
            elif subject_pending:
                # a by-place range (pseudocode): the range's subject is the
                # function; its name anchor arrives on the first line
                for a in ln.anchors:
                    if (a.flags & ida_lines.LAF_INCOMING) \
                       and a.identifier.startswith("sym-"):
                        funcs.append((ida_name.get_short_name(subject)
                                      or _anchor_name(a.identifier),
                                      a.identifier))
                        subject_pending = False
                        break
            if ea == ida_idaapi.BADADDR:
                ea = subject
            row_ea.append(ea)
            if ea != ida_idaapi.BADADDR:
                lo = ea if lo is None else min(lo, ea)
                hi = ea if hi is None else max(hi, ea)
            rows.append(ln.text)
        if gen.was_cancelled():
            cancelled = True
            break
    style = style or ""
    fg = _ida_listing_css_value(style, "color") or "#000"
    bg = _ida_listing_css_value(style, "background-color") or "#fff"

    # cancel: the page is assembled only below, so bail before that work (nothing
    # written yet; the C++ side drops any partial file)
    if cancelled:
        return

    # gutter edges: keep only function-local reference->definition pairs
    def _func_start(ea):
        if ea == ida_idaapi.BADADDR:
            return None
        fs = ida_funcs.get_func_start(ea)
        return None if fs == ida_idaapi.BADADDR else fs

    # group edges by function so the browser lane-packs each lazily, on scroll
    func_edges = {}
    for s, i in out_edges:
        d = defs.get(i)
        if d is None:
            continue
        fs = _func_start(row_ea[s])
        if fs is None or fs != _func_start(row_ea[d]):
            continue
        # drop arrows to the function entry (whole-function span, no control flow)
        if row_ea[d] == fs:
            continue
        func_edges.setdefault(fs, []).append([s, d])
    # one group per function: [minRow, maxRow, [[src,dst],...]]
    edges = []
    for grp in func_edges.values():
        span = [r for e in grp for r in e]
        edges.append([min(span), max(span), grp])

    # gutter/checkbox/JS only when there are arrows (a by-place listing has none)
    has_arrows = len(edges) > 0

    fname = ida_nalt.get_root_filename() or "?"
    rng = ("%X-%X" % (lo, hi)) if lo is not None else "?"
    meta = ("module <b>%s</b> &nbsp; range <b>%s</b> &nbsp; <b>%d</b> lines "
            "&nbsp; %s"
            % (_esc(fname), rng, len(rows), _esc(doc_title)))
    root_vars = (":root{--gutter:%s;--arrow:#3b82f6;--arrow-up:#e08a3c;"
                 "--bg:%s;--fg:%s}\n"
                 % ("72px" if has_arrows else "0px", bg, fg))

    # sidebar entries: functions in a disassembly, else the type definitions
    # (ty-<name> anchors) of a type listing (IDA-7601).
    from urllib.parse import unquote
    types = [(unquote(i[3:]), i) for i in defs if i.startswith("ty-")]
    entries = funcs if funcs else types
    fl_label = "functions" if funcs else "types"
    # only worth a sidebar when there is more than one entry to jump between
    show_fnlist = len(entries) > 1
    body_cls = ' class="has-fnlist"' if show_fnlist else ''
    fl_toggle = ('<label><input type="checkbox" id="t-fl" checked> %s</label>'
                 % fl_label if show_fnlist else '')
    ar_toggle = ('<label><input type="checkbox" id="t-ar" checked>'
                 ' arrows</label>' if has_arrows else '')
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write('<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n'
                 '<meta name="viewport" content="width=device-width,'
                 ' initial-scale=1">\n<title>%s</title>\n<style>\n%s%s%s</style>\n'
                 '</head>\n<body%s>\n'
                 % (_esc(doc_title), root_vars, style, _CSS, body_cls))
        fh.write('<div class="tb">'
                 '%s%s'
                 '<label><input type="checkbox" id="t-pfx" checked> prefix</label>'
                 '<label><input type="checkbox" id="t-xr" checked> xrefs</label>'
                 '<label><input type="checkbox" id="t-cm" checked> comments</label>'
                 '</div>\n' % (fl_toggle, ar_toggle))
        if show_fnlist:
            fh.write('<nav class="fnlist">\n')
            for name, ident in entries:
                fh.write('<a href="#%s">%s</a>\n' % (ident, _esc(name)))
            fh.write('</nav>\n')
        fh.write('<div class="meta">%s</div>\n' % meta)
        gutter_svg = ('<svg class="agut" id="agut"'
                      ' xmlns="http://www.w3.org/2000/svg"></svg>'
                      if has_arrows else '')
        fh.write('<div class="code-wrap ida-listing" id="cw">%s\n' % gutter_svg)
        # anchors/links are already inline in the line text; a row is just its
        # text. Chunk rows in <section class="ck"> (no inter-row newlines).
        CHUNK = 500
        for i in range(0, len(rows), CHUNK):
            part = rows[i:i + CHUNK]
            fh.write('<section class="ck" style="--n:%d">%s</section>\n'
                     % (len(part),
                        "".join('<div class="row">%s</div>' % h for h in part)))
        fh.write('</div>\n')
        if has_arrows:
            fh.write('<script>var EDGES=%s;</script>\n' % json.dumps(edges))
            fh.write('<script>%s</script>\n' % _JS)
        fh.write('<script>%s</script>\n' % _TOGGLE_JS)
        fh.write('</body>\n</html>\n')
