#!/bin/sh
# ghostwire portátil — corre desde el USB, no toca el disco del ordenador.
#
# TODO lo que ghostwire y su tor escriben (datos de tor, temporales, la clave
# de la sesión) vive DENTRO de esta carpeta del USB. Nada va al disco del host.
# Al sacar el USB no queda rastro de la conversación por parte de ghostwire.
#
# Lo que ghostwire NO puede borrar es lo que el propio sistema del ordenador
# apunte por su cuenta (el registro de que se montó un USB, la swap, el
# journal). Para CERO rastro de verdad hay que arrancar el ordenador DESDE un
# USB amnésico (Tails) — ver LEEME.txt.
set -eu

# Raíz = la carpeta donde está este script, sea cual sea la letra del USB.
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

# Encierra HOME, temporales y config dentro del USB. Cualquier cosa que un
# programa intente escribir en "el home" o en /tmp cae aquí, no en el host.
export HOME="$HERE/home"
export TMPDIR="$HERE/tmp"
export XDG_CONFIG_HOME="$HERE/home/.config"
export XDG_CACHE_HOME="$HERE/home/.cache"
mkdir -p "$HOME" "$TMPDIR" "$HERE/tor/data"
chmod 700 "$HERE/tor/data"

# --- config ---
RELAY="${GW_RELAY:-4f55szire2l7yfblkty2jism6lzshvm6x3ydlappjuab6w3pgmsvpoad.onion:1717}"
NICK="${GW_NICK:-anon}"
SOCKS_PORT=19599   # puerto alto propio para no chocar con un tor del host

TOR="$HERE/tor/tor"
GW="$HERE/bin/gw"
export LD_LIBRARY_PATH="$HERE/tor/lib"

cleanup() {
	[ -n "${TOR_PID:-}" ] && kill "$TOR_PID" 2>/dev/null || true
	# Borra los datos efímeros de tor de esta sesión (descriptores, estado).
	# La clave onion no está aquí: este tor es solo cliente.
	rm -rf "$HERE/tor/data" "$TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

printf '\033[36mghostwire portátil\033[0m — arrancando tor desde el USB…\n' >&2

# tor cliente, datos en el USB, SOCKS en un puerto alto propio.
#  -f /dev/null --ignore-missing-torrc : NO heredar el torrc del host (un USB
#     portátil no debe depender de la config del ordenador ajeno).
#  --ControlPort 0 : no abrir control port (chocaba con un tor del host y no
#     lo necesitamos: este tor es solo cliente SOCKS).
"$TOR" \
	-f /dev/null --ignore-missing-torrc \
	--SocksPort "127.0.0.1:$SOCKS_PORT" \
	--ControlPort 0 \
	--DataDirectory "$HERE/tor/data" \
	--ClientOnly 1 \
	--AvoidDiskWrites 1 \
	--Log "notice file $HERE/tor/data/tor.log" \
	>/dev/null 2>&1 &
TOR_PID=$!

# Espera a que tor esté al 100% (o ríndete a los 90 s).
printf 'construyendo circuito ' >&2
i=0
while [ $i -lt 90 ]; do
	if grep -q 'Bootstrapped 100%' "$HERE/tor/data/tor.log" 2>/dev/null; then
		break
	fi
	if ! kill -0 "$TOR_PID" 2>/dev/null; then
		printf '\n\033[31mtor no arrancó\033[0m — mira %s\n' "$HERE/tor/data/tor.log" >&2
		exit 1
	fi
	printf '.' >&2
	sleep 1
	i=$((i + 1))
done
printf ' listo\n\n' >&2

# El cliente. Relay, nick y SOCKS van por ENTORNO, no por flags: así "$@" puede
# empezar por un subcomando (pipe/tail) — gw solo lo reconoce si es el primer
# argumento. Sin argumentos → interfaz interactiva. Identidad efímera (en RAM),
# la passphrase se pide a ciegas.
export GW_RELAY="$RELAY"
export GW_NICK="$NICK"
export GW_TOR_SOCKS="127.0.0.1:$SOCKS_PORT"

# En primer plano, NO exec: si reemplazáramos el shell, el `trap cleanup` no se
# ejecutaría y el tor del USB quedaría huérfano ocupando el puerto. Al volver
# gw, el trap EXIT mata tor y borra los datos efímeros.
"$GW" "$@"
