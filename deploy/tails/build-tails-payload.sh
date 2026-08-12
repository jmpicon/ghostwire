#!/bin/sh
# Copia lo que hay que soltar dentro de Tails a una carpeta destino.
#   ./build-tails-payload.sh /ruta/destino   (p.ej. un USB normal para llevarlo a Tails)
# Dentro de Tails, esos archivos van a ~/Persistent/ y se hace chmod +x.
set -eu
DEST="${1:?uso: build-tails-payload.sh <carpeta-destino>}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
GW="${GW_BIN:-$HOME/go/bin/gw}"
[ -x "$GW" ] || { echo "falta gw estático en $GW (make build)" >&2; exit 1; }
# gw DEBE ser estático: Tails no tiene tus bibliotecas.
if file "$GW" | grep -q 'dynamically linked'; then
	echo "gw está enlazado dinámicamente; recompílalo con CGO_ENABLED=0 (make build)" >&2
	exit 1
fi
mkdir -p "$DEST"
cp "$GW" "$DEST/gw"
cp "$HERE/ghostwire-tails.sh" "$HERE/LEEME-TAILS.txt" "$DEST/"
chmod +x "$DEST/gw" "$DEST/ghostwire-tails.sh"
echo "payload de Tails listo en $DEST"
echo "llévalo a Tails y cópialo a ~/Persistent/ (ver LEEME-TAILS.txt)"
