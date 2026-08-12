#!/bin/sh
# ghostwire dentro de Tails — el cero-rastro de verdad.
#
# Tails ya ES el sistema amnésico: arrancas el ordenador DESDE el USB de Tails,
# el disco del ordenador ni se toca, todo corre en RAM, y al apagar la RAM se
# borra. Esto no lo puede dar un programa portátil: solo lo da no usar el
# sistema del ordenador ajeno. Tails además ya trae Tor corriendo y bloquea con
# su cortafuegos cualquier tráfico que NO vaya por Tor.
#
# Este lanzador solo apunta gw al Tor de Tails y al relay. No arranca ningún
# tor: el de Tails ya está.
set -eu

# Tails expone su Tor en el puerto SOCKS estándar. El usuario `amnesia` tiene
# permiso del cortafuegos para alcanzarlo.
export GW_TOR_SOCKS="127.0.0.1:9050"

# Relay por defecto: tu Raspberry. Cámbialo con  GW_RELAY=<otro>.onion:1717
export GW_RELAY="${GW_RELAY:-4f55szire2l7yfblkty2jism6lzshvm6x3ydlappjuab6w3pgmsvpoad.onion:1717}"
export GW_NICK="${GW_NICK:-anon}"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
GW="$HERE/gw"

# Si el Almacenamiento Persistente está montado sin permiso de ejecución, el
# binario no arranca desde ahí. /tmp en Tails es RAM (amnésico y ejecutable):
# se copia allí y se ejecuta, sin tocar ningún disco.
if [ ! -x "$GW" ] || ! "$GW" version >/dev/null 2>&1; then
	cp "$GW" /tmp/gw 2>/dev/null || { echo "no puedo preparar gw" >&2; exit 1; }
	chmod +x /tmp/gw
	GW=/tmp/gw
fi

# Identidad efímera (en RAM) por defecto: es lo coherente con Tails. Sin
# argumentos → interfaz de chat. `pipe`/`tail` para automatización.
exec "$GW" "$@"
