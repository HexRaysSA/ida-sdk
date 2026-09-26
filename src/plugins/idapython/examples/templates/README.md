# Produce-HTML templates

These render the output of IDA's "Export to HTML" dialog, which lists every
non-underscore `*.py` in this directory. Copy one to add your own.

The contract:

- `title` / `description` — module-level strings labelling the dialog entry.
- `run(out_path, cfg)` — writes the file. `cfg` is the `export_listing_t` to render; `cfg.create_lines(flags, range_index)` yields one range's lines.
