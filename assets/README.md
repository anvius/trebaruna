# Assets

`icons/trebaruna-{64,128,256,512}.png` are the application icon at the sizes
packagers expect: `64` and `128` for desktop entries, `256` for the window
manager, `512` for stores and installers.

`src/desktop/infrastructure/assets/icons/trebaruna-256.png` is a copy used by
`//go:embed`. Go's embed directive does not accept `..` paths, so the file has
to live inside the package directory. The copy is byte-identical to the one
here; if you regenerate the icon, copy it over:

```bash
cp assets/icons/trebaruna-256.png src/desktop/infrastructure/assets/icons/
```

The icon is generated, not hand-drawn: a rounded slate tile, a white page with
text lines, and a teal seal with a check. It is deliberately legible at 16 px,
because that is the size that matters in a taskbar.
