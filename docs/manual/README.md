# Manual de usuario de la app (iec61850-tauri)

- `manual-usuario-app.pdf` — manual listo para distribuir (11 págs, A4).
- `manual-usuario-app.html` — fuente. Regenerar el PDF:

```sh
google-chrome --headless --disable-gpu \
  --print-to-pdf=manual-usuario-app.pdf --no-pdf-header-footer \
  manual-usuario-app.html
```

Los datos de ejemplo provienen del CID «LT-SJA (ES-VAL)» (ABB/Hitachi, IET600)
servido con `iec61850-sim`.
