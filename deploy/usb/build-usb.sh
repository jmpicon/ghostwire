#!/bin/sh
# Arma el bundle portátil de ghostwire para un USB Linux x86-64.
#   ./build-usb.sh /ruta/al/destino
# Copia el gw estático, el tor del sistema con sus bibliotecas, y el lanzador.
set -eu
DEST="${1:?uso: build-usb.sh <carpeta-destino>}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
GW="${GW_BIN:-$HOME/go/bin/gw}"
TOR="${TOR_BIN:-/usr/bin/tor}"

[ -x "$GW" ]  || { echo "falta gw estático en $GW (compílalo: make build)" >&2; exit 1; }
[ -x "$TOR" ] || { echo "falta tor en $TOR (apt install tor)" >&2; exit 1; }

mkdir -p "$DEST/bin" "$DEST/tor/lib"
cp "$GW"  "$DEST/bin/gw"
cp "$TOR" "$DEST/tor/tor"
# bibliotecas de tor salvo las de glibc (esas las pone el host)
ldd "$TOR" | awk '/=>/{print $3}' \
  | grep -viE '/libc\.so|/libm\.so|/libpthread|/libdl\.so|/ld-linux' \
  | while read -r lib; do cp -L "$lib" "$DEST/tor/lib/"; done
cp "$HERE/ghostwire.sh" "$HERE/LEEME.txt" "$HERE/ghostwire-doble-clic.desktop" "$DEST/"
chmod +x "$DEST/ghostwire.sh" "$DEST/bin/gw" "$DEST/tor/tor"
echo "bundle listo en $DEST ($(du -sh "$DEST" | cut -f1))"
echo "cópialo a la partición de datos del USB y ejecútalo con ./ghostwire.sh"
