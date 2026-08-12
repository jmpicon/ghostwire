// Command gw-desktop is the graphical ghostwire client.
//
// It is a native window, not a browser: no webview, no JavaScript, no bundled
// Chromium. That is a security decision, not an aesthetic one. A web UI means
// something serves you the code that handles your passphrase, which is the
// single best place to hide a backdoor in a tool like this.
//
// The window is a thin shell over internal/client — the same code the terminal
// client uses, so both speak the identical protocol and share one
// implementation of every security-relevant decision.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/jmpicon/ghostwire/internal/client"
	gcrypto "github.com/jmpicon/ghostwire/internal/crypto"
	"github.com/jmpicon/ghostwire/internal/launch"
	"github.com/jmpicon/ghostwire/internal/tor"
)

var version = "dev"

// maxLines is the per-channel scrollback. Everything lives in RAM and dies
// with the process — the desktop client writes no history to disk either.
const maxLines = 2000

type gui struct {
	win fyne.Window
	cli *client.Client

	mu      sync.Mutex
	order   []string
	buffers map[string][]string
	current string
	viaTor  bool
	relay   string
	linkUp  bool

	channels *widget.List
	messages *widget.List
	members  *widget.Label
	input    *widget.Entry
	status   *widget.Label
}

func main() {
	relay := flag.String("relay", launch.Env("GW_RELAY", ""), "relay address, normally <56chars>.onion:1717")
	socks := flag.String("tor", launch.Env("GW_TOR_SOCKS", tor.DefaultSOCKS), "tor SOCKS5 address")
	clearnet := flag.Bool("clearnet", false, "connect without tor (exposes your IP to the relay)")
	nick := flag.String("nick", launch.Env("GW_NICK", "anon"), "cosmetic display name")
	identity := flag.String("identity", launch.Env("GW_IDENTITY", ""), "persistent identity seed file (default: ephemeral)")
	noise := flag.Duration("noise", 20*time.Second, "mean cover-traffic interval (0 disables padding)")
	jitter := flag.Duration("jitter", 400*time.Millisecond, "maximum random delay before sending")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gw-desktop %s\n", version)
		return
	}

	a := fyneapp.NewWithID("com.neuralghost.ghostwire")
	w := a.NewWindow("ghostwire")
	w.Resize(fyne.NewSize(940, 620))

	dial, viaTor, err := launch.Transport(*relay, *socks, *clearnet)
	if err != nil {
		fatalWindow(a, w, err)
		return
	}
	id, err := launch.Identity(*identity)
	if err != nil {
		fatalWindow(a, w, err)
		return
	}
	cli, err := client.New(client.Config{
		Addr:       *relay,
		Dial:       dial,
		Identity:   id,
		Nick:       *nick,
		NoiseMean:  *noise,
		SendJitter: *jitter,
		Reconnect:  true,
	})
	if err != nil {
		fatalWindow(a, w, err)
		return
	}

	g := &gui{
		win:     w,
		cli:     cli,
		buffers: map[string][]string{},
		relay:   *relay,
		viaTor:  viaTor,
	}
	g.build()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { _ = cli.Run(ctx) }()
	go g.pump(ctx)

	a.Lifecycle().SetOnStarted(func() {
		go func() {
			g.say("*ghostwire", fmt.Sprintf("identidad %s  ·  relay %s", cli.Fingerprint(), *relay))
			if viaTor {
				g.say("*ghostwire", "transporte: servicio onion de tor, circuito aislado")
			} else {
				g.say("*ghostwire", "AVISO: sin tor — el relay ve tu dirección IP")
			}
			g.say("*ghostwire", "Pulsa «Entrar en un canal» para empezar.")
			g.say("*ghostwire", "El canal es el nombre MÁS la passphrase: no hay registro en ningún sitio.")
			g.refresh()
		}()
	})

	w.SetCloseIntercept(func() { cli.Close(); stop(); w.Close() })
	w.ShowAndRun()
}

func fatalWindow(a fyne.App, w fyne.Window, err error) {
	w.SetContent(container.NewVBox(
		widget.NewLabelWithStyle("No se puede arrancar", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel(err.Error()),
		widget.NewButton("Cerrar", func() { a.Quit() }),
	))
	w.Resize(fyne.NewSize(680, 220))
	w.ShowAndRun()
}

// ---- construcción de la ventana -------------------------------------------

func (g *gui) build() {
	g.channels = widget.NewList(
		func() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.order) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			g.mu.Lock()
			defer g.mu.Unlock()
			if i < len(g.order) {
				o.(*widget.Label).SetText(g.order[i])
			}
		},
	)
	g.channels.OnSelected = func(i widget.ListItemID) {
		g.mu.Lock()
		if i < len(g.order) {
			g.current = g.order[i]
		}
		g.mu.Unlock()
		go g.refresh()
	}

	g.messages = widget.NewList(
		func() int { return len(g.lines()) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.Wrapping = fyne.TextWrapWord
			return l
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			lines := g.lines()
			if i < len(lines) {
				o.(*widget.Label).SetText(lines[i])
			}
		},
	)

	g.members = widget.NewLabel("")
	g.members.Wrapping = fyne.TextWrapWord

	g.input = widget.NewEntry()
	g.input.SetPlaceHolder("Escribe y pulsa Enter…")
	g.input.OnSubmitted = func(s string) {
		g.send(s)
		g.input.SetText("")
	}

	g.status = widget.NewLabel("conectando…")

	join := widget.NewButtonWithIcon("Entrar en un canal", theme.ContentAddIcon(), g.askJoin)
	part := widget.NewButtonWithIcon("Salir del canal", theme.ContentRemoveIcon(), g.partCurrent)
	panic_ := widget.NewButtonWithIcon("PÁNICO", theme.WarningIcon(), g.askPanic)

	left := container.NewBorder(
		widget.NewLabelWithStyle("Canales", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewVBox(join, part), nil, nil, g.channels)

	right := container.NewBorder(
		widget.NewLabelWithStyle("Quién ha hablado", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil, container.NewVScroll(g.members))

	centre := container.NewBorder(nil, g.input, nil, nil, g.messages)

	body := container.NewBorder(nil, nil,
		newSized(left, 210), newSized(right, 210), centre)

	g.win.SetContent(container.NewBorder(
		nil, container.NewBorder(nil, nil, nil, panic_, g.status), nil, nil, body))
	g.win.Canvas().Focus(g.input)

	g.ensure("*ghostwire")
	g.current = "*ghostwire"
}

// newSized pins a panel to a fixed width so the chat gets the remaining space.
func newSized(o fyne.CanvasObject, w float32) fyne.CanvasObject {
	r := container.NewStack(o)
	r.Resize(fyne.NewSize(w, r.MinSize().Height))
	return container.New(&fixedWidth{w: w}, r)
}

type fixedWidth struct{ w float32 }

func (f *fixedWidth) MinSize(objs []fyne.CanvasObject) fyne.Size {
	h := float32(0)
	for _, o := range objs {
		if m := o.MinSize().Height; m > h {
			h = m
		}
	}
	return fyne.NewSize(f.w, h)
}

func (f *fixedWidth) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objs {
		o.Resize(fyne.NewSize(f.w, size.Height))
		o.Move(fyne.NewPos(0, 0))
	}
}

// ---- acciones --------------------------------------------------------------

func (g *gui) askJoin() {
	name := widget.NewEntry()
	name.SetPlaceHolder("#ops")
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("la passphrase acordada")

	form := dialog.NewForm("Entrar en un canal", "Entrar", "Cancelar",
		[]*widget.FormItem{
			widget.NewFormItem("Canal", name),
			widget.NewFormItem("Passphrase", pass),
		},
		func(ok bool) {
			if !ok || strings.TrimSpace(name.Text) == "" || pass.Text == "" {
				return
			}
			ch := gcrypto.NormalizeChannel(name.Text)
			g.ensure(ch)
			g.selectChannel(ch)
			g.say(ch, "derivando la clave del canal (argon2id, ~64 MiB)…")
			go g.refresh()
			// Argon2id takes real CPU time on purpose — never on the UI thread.
			go func(ch, p string) {
				if err := g.cli.Join(ch, p); err != nil {
					g.say(ch, "error: "+err.Error())
				}
				g.refresh()
			}(ch, pass.Text)
		}, g.win)
	form.Resize(fyne.NewSize(420, 200))
	form.Show()
}

func (g *gui) partCurrent() {
	cur := g.currentChannel()
	if !strings.HasPrefix(cur, "#") {
		return
	}
	if err := g.cli.Part(cur); err != nil {
		g.say(cur, "error: "+err.Error())
		go g.refresh()
		return
	}
	g.mu.Lock()
	delete(g.buffers, cur)
	for i, n := range g.order {
		if n == cur {
			g.order = append(g.order[:i], g.order[i+1:]...)
			break
		}
	}
	g.current = "*ghostwire"
	g.mu.Unlock()
	go g.refresh()
}

func (g *gui) askPanic() {
	dialog.ShowConfirm("Pánico",
		"Borra TODAS las claves de la memoria y cierra el programa inmediatamente.\n\n"+
			"No hay confirmación después de esta. ¿Seguro?",
		func(ok bool) {
			if !ok {
				return
			}
			g.cli.Panic()
			os.Exit(0)
		}, g.win)
}

func (g *gui) send(text string) {
	text = strings.TrimSpace(text)
	cur := g.currentChannel()
	if text == "" || !strings.HasPrefix(cur, "#") {
		return
	}
	if err := g.cli.Say(cur, text); err != nil {
		g.say(cur, "error: "+err.Error())
		go g.refresh()
	}
}

// ---- eventos ---------------------------------------------------------------

func (g *gui) pump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-g.cli.Events():
			if !ok {
				return
			}
			g.onEvent(ev)
			g.refresh()
		}
	}
}

func (g *gui) onEvent(ev client.Event) {
	switch ev.Kind {
	case client.EvConnected:
		g.mu.Lock()
		g.linkUp = true
		g.mu.Unlock()
		g.say("*ghostwire", "enlace establecido con "+ev.Text)
	case client.EvDisconnected:
		g.mu.Lock()
		g.linkUp = false
		g.mu.Unlock()
		g.say("*ghostwire", "enlace caído ("+ev.Text+") — reintentando")
	case client.EvError:
		g.say(g.currentChannel(), "relay: "+ev.Text)
	case client.EvSystem:
		g.say(ev.Channel, ev.Text)
	case client.EvPresence:
		m := ev.Msg
		who := fmt.Sprintf("%s#%s", m.Nick, gcrypto.Short(m.Fingerprint()))
		switch {
		case m.Body == "join":
			g.say(ev.Channel, fmt.Sprintf("[+] %s está aquí", who))
		case m.Body == "part":
			g.say(ev.Channel, fmt.Sprintf("[-] %s se ha ido", who))
		case strings.HasPrefix(m.Body, "nick "):
			g.say(ev.Channel, fmt.Sprintf("[~] %s antes era %s", who, strings.TrimPrefix(m.Body, "nick ")))
		}
	case client.EvMessage:
		m := ev.Msg
		g.say(ev.Channel, fmt.Sprintf("%s  %s#%s  %s",
			m.Sent.Local().Format("15:04"), m.Nick, gcrypto.Short(m.Fingerprint()), m.Body))
	}
}

// ---- estado y pintado ------------------------------------------------------

func (g *gui) ensure(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.buffers[name]; ok {
		return
	}
	g.buffers[name] = nil
	g.order = append(g.order, name)
	sort.SliceStable(g.order[1:], func(i, j int) bool { return g.order[1+i] < g.order[1+j] })
}

func (g *gui) say(channel, line string) {
	if channel == "" {
		channel = "*ghostwire"
	}
	g.ensure(channel)
	g.mu.Lock()
	b := append(g.buffers[channel], line)
	if len(b) > maxLines {
		b = b[len(b)-maxLines:]
	}
	g.buffers[channel] = b
	g.mu.Unlock()
}

func (g *gui) lines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, len(g.buffers[g.current]))
	copy(out, g.buffers[g.current])
	return out
}

func (g *gui) currentChannel() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.current
}

func (g *gui) selectChannel(name string) {
	g.mu.Lock()
	for i, n := range g.order {
		if n == name {
			g.current = name
			g.mu.Unlock()
			g.channels.Select(i)
			return
		}
	}
	g.mu.Unlock()
}

// refresh repaints. Every caller may be on a background goroutine, so the work
// is handed to the UI thread — Fyne is not safe to touch from anywhere else.
func (g *gui) refresh() {
	fyne.Do(func() {
		cur := g.currentChannel()

		var sb strings.Builder
		if strings.HasPrefix(cur, "#") {
			ms := g.cli.Members(cur)
			fmt.Fprintf(&sb, "%d han hablado\n\n", len(ms))
			for _, m := range ms {
				mark := " "
				if m.Self {
					mark = "•"
				}
				fmt.Fprintf(&sb, "%s %s\n   %s\n", mark, m.Nick, gcrypto.Short(m.Fingerprint))
			}
			if len(ms) == 0 {
				sb.WriteString("Nadie todavía.\nEl silencio es invisible:\nno hay lista de conectados.")
			}
		} else {
			sb.WriteString("(no es un canal)")
		}
		g.members.SetText(sb.String())

		link := "sin enlace"
		g.mu.Lock()
		if g.linkUp {
			link = "conectado"
		}
		g.mu.Unlock()
		transport := "CLEARNET — el relay ve tu IP"
		if g.viaTor {
			transport = "tor"
		}
		g.status.SetText(fmt.Sprintf("%s · %s · %s#%s",
			transport, link, g.cli.Nick(), gcrypto.Short(g.cli.Fingerprint())))

		g.channels.Refresh()
		g.messages.Refresh()
		if n := len(g.lines()); n > 0 {
			g.messages.ScrollToBottom()
		}
	})
}
