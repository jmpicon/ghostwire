// Package ui renders the IRC-shaped terminal client.
package ui

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/jmpicon/ghostwire/internal/client"
	gcrypto "github.com/jmpicon/ghostwire/internal/crypto"
)

const statusBuffer = "*ghostwire"

var nickPalette = []string{
	"green", "yellow", "blue", "fuchsia", "aqua", "orange",
	"lime", "teal", "olive", "purple",
}

// TUI is the terminal front-end.
type TUI struct {
	app    *tview.Application
	pages  *tview.Pages
	chat   *tview.TextView
	roster *tview.TextView
	status *tview.TextView
	input  *tview.InputField

	cli    *client.Client
	relay  string
	viaTor bool

	bufs    map[string]*buffer
	order   []string
	current string

	cancel context.CancelFunc
}

// New wires the widgets together.
func New(cli *client.Client, relay string, viaTor bool, cancel context.CancelFunc) *TUI {
	t := &TUI{
		app:     tview.NewApplication(),
		pages:   tview.NewPages(),
		cli:     cli,
		relay:   relay,
		viaTor:  viaTor,
		bufs:    map[string]*buffer{},
		order:   []string{},
		cancel:  cancel,
		current: statusBuffer,
	}
	t.bufs[statusBuffer] = newBuffer(statusBuffer)
	t.order = append(t.order, statusBuffer)

	t.chat = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(true).
		SetWordWrap(true)
	t.chat.SetBorder(true).SetBorderColor(tcell.ColorTeal)

	t.roster = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	t.roster.SetBorder(true).SetTitle(" who spoke ")

	t.status = tview.NewTextView().SetDynamicColors(true)

	t.input = tview.NewInputField().SetFieldWidth(0)
	t.input.SetFieldBackgroundColor(tcell.ColorBlack)
	t.input.SetLabel("» ")
	t.input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		line := t.input.GetText()
		t.input.SetText("")
		t.handle(line)
	})

	body := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(t.chat, 0, 1, false).
		AddItem(t.roster, 26, 0, false)

	main := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.status, 1, 0, false).
		AddItem(body, 0, 1, false).
		AddItem(t.input, 1, 0, true)

	t.pages.AddPage("main", main, true, true)
	t.app.SetRoot(t.pages, true).SetFocus(t.input)
	t.app.SetInputCapture(t.keys)
	return t
}

func (t *TUI) keys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyCtrlN:
		t.cycle(1)
		return nil
	case tcell.KeyCtrlP:
		t.cycle(-1)
		return nil
	case tcell.KeyCtrlL:
		t.buf(t.current).clear()
		t.redraw()
		return nil
	case tcell.KeyPgUp:
		row, _ := t.chat.GetScrollOffset()
		t.chat.ScrollTo(row-10, 0)
		return nil
	case tcell.KeyPgDn:
		row, _ := t.chat.GetScrollOffset()
		t.chat.ScrollTo(row+10, 0)
		return nil
	}
	return ev
}

// Run starts the event pump and blocks until the UI exits.
func (t *TUI) Run(ctx context.Context, autojoin []Autojoin) error {
	t.banner()
	go t.pump(ctx)
	go func() {
		// Give the transport a moment to come up before joining, so the
		// JOIN cells ride the same circuit as the HELLO.
		time.Sleep(300 * time.Millisecond)
		for _, a := range autojoin {
			if err := t.cli.Join(a.Name, a.Passphrase); err != nil {
				t.sys(statusBuffer, "[red]join %s: %v", a.Name, err)
			}
		}
		t.app.QueueUpdateDraw(func() {})
	}()
	return t.app.Run()
}

// Autojoin is a channel to enter at startup.
type Autojoin struct {
	Name       string
	Passphrase string
}

func (t *TUI) pump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-t.cli.Events():
			if !ok {
				return
			}
			t.onEvent(ev)
		}
	}
}

func (t *TUI) onEvent(ev client.Event) {
	switch ev.Kind {
	case client.EvConnected:
		t.sys(statusBuffer, "[green]link up[-] → %s", ev.Text)
	case client.EvDisconnected:
		t.sys(statusBuffer, "[red]link down[-] (%s)", ev.Text)
	case client.EvError:
		t.sys(t.current, "[red]%s", ev.Text)
	case client.EvSystem:
		t.sys(t.bufferFor(ev.Channel), "[gray]%s", ev.Text)
	case client.EvPresence:
		t.presence(ev)
	case client.EvMessage:
		t.message(ev)
	}
	t.app.QueueUpdateDraw(func() { t.refresh() })
}

func (t *TUI) message(ev client.Event) {
	m := ev.Msg
	name := t.bufferFor(ev.Channel)
	t.ensure(name)

	who := renderNick(m.Nick, m.Fingerprint())
	ts := m.Sent.Local().Format("15:04")
	body := tview.Escape(m.Body)

	if m.Kind == gcrypto.KindAction {
		t.line(name, "[gray]%s[-] [gray]*[-] %s %s", ts, who, body)
		return
	}
	t.line(name, "[gray]%s[-] %s %s", ts, who, body)
}

func (t *TUI) presence(ev client.Event) {
	m := ev.Msg
	name := t.bufferFor(ev.Channel)
	who := renderNick(m.Nick, m.Fingerprint())
	ts := m.Sent.Local().Format("15:04")

	switch {
	case m.Body == "join":
		t.line(name, "[gray]%s[-] [green]→[-] %s is here", ts, who)
	case m.Body == "part":
		t.line(name, "[gray]%s[-] [red]←[-] %s left", ts, who)
	case strings.HasPrefix(m.Body, "nick "):
		old := tview.Escape(strings.TrimPrefix(m.Body, "nick "))
		t.line(name, "[gray]%s[-] [yellow]~[-] %s was %s", ts, who, old)
	}
}

func (t *TUI) banner() {
	for _, l := range strings.Split(bannerArt, "\n") {
		t.line(statusBuffer, "[teal]%s", l)
	}
	t.sys(statusBuffer, "identity  [white]%s[-]   (ephemeral unless -i was given)", t.cli.Fingerprint())
	t.sys(statusBuffer, "nick      [white]%s", t.cli.Nick())
	t.sys(statusBuffer, "relay     [white]%s", t.relay)
	if t.viaTor {
		t.sys(statusBuffer, "transport [green]tor onion service[-] · stream-isolated circuit")
	} else {
		t.sys(statusBuffer, "transport [red]CLEARNET — the relay sees your IP address[-]")
	}
	t.sys(statusBuffer, "")
	t.sys(statusBuffer, "[gray]/join #room[-]  ·  [gray]/help[-] for everything else  ·  [gray]^N ^P[-] switch window")
}

// ---- commands -------------------------------------------------------------

func (t *TUI) handle(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if !strings.HasPrefix(line, "/") {
		t.say(t.current, line)
		t.refresh()
		return
	}

	parts := strings.SplitN(line[1:], " ", 2)
	cmd := strings.ToLower(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = strings.TrimSpace(parts[1])
	}

	switch cmd {
	case "join", "j":
		t.cmdJoin(rest)
	case "part", "leave":
		t.cmdPart(rest)
	case "nick":
		if rest == "" {
			t.sys(t.current, "[red]usage: /nick <name>")
			break
		}
		t.cli.SetNick(rest)
		t.sys(t.current, "[gray]you are now %s (fingerprint unchanged: %s)", tview.Escape(rest), t.cli.Fingerprint())
	case "me":
		if isChannel(t.current) && rest != "" {
			if err := t.cli.Action(t.current, rest); err != nil {
				t.sys(t.current, "[red]%v", err)
			}
		}
	case "msg":
		sub := strings.SplitN(rest, " ", 2)
		if len(sub) < 2 {
			t.sys(t.current, "[red]usage: /msg #channel <text>")
			break
		}
		t.say(gcrypto.NormalizeChannel(sub[0]), sub[1])
	case "names", "who":
		t.cmdNames()
	case "keys", "fp":
		t.sys(t.current, "your fingerprint: [white]%s", t.cli.Fingerprint())
		t.sys(t.current, "[gray]verify it out of band. nicknames are decoration, fingerprints are not.")
	case "whois":
		t.cmdWhois(rest)
	case "win", "w":
		t.cmdWin(rest)
	case "next":
		t.cycle(1)
	case "prev":
		t.cycle(-1)
	case "clear":
		t.buf(t.current).clear()
	case "help", "h", "?":
		t.cmdHelp()
	case "panic":
		t.cli.Panic()
		t.app.Stop()
		fmt.Println("keys wiped.")
	case "quit", "q", "exit":
		t.cli.Close()
		t.cancel()
		t.app.Stop()
	default:
		t.sys(t.current, "[red]unknown command /%s[-]  (try /help)", tview.Escape(cmd))
	}
	t.refresh()
}

func (t *TUI) cmdJoin(rest string) {
	if rest == "" {
		t.sys(t.current, "[red]usage: /join #channel [passphrase]")
		return
	}
	fields := strings.SplitN(rest, " ", 2)
	name := gcrypto.NormalizeChannel(fields[0])
	if len(fields) == 2 && fields[1] != "" {
		t.doJoin(name, fields[1])
		return
	}
	t.prompt(fmt.Sprintf("passphrase for %s", name), func(pass string) {
		if pass == "" {
			t.sys(statusBuffer, "[red]join aborted: empty passphrase")
			return
		}
		t.doJoin(name, pass)
	})
}

func (t *TUI) doJoin(name, pass string) {
	t.ensure(name)
	t.switchTo(name)
	t.sys(name, "[gray]deriving channel key (argon2id, ~64 MiB)…")
	t.refresh()

	go func() {
		err := t.cli.Join(name, pass)
		t.app.QueueUpdateDraw(func() {
			if err != nil {
				t.sys(name, "[red]%v", err)
			}
			t.refresh()
		})
	}()
}

func (t *TUI) cmdPart(rest string) {
	name := t.current
	if rest != "" {
		name = gcrypto.NormalizeChannel(rest)
	}
	if !isChannel(name) {
		t.sys(t.current, "[red]not a channel")
		return
	}
	if err := t.cli.Part(name); err != nil {
		t.sys(t.current, "[red]%v", err)
		return
	}
	t.drop(name)
}

func (t *TUI) cmdNames() {
	if !isChannel(t.current) {
		t.sys(t.current, "[red]not a channel")
		return
	}
	ms := t.cli.Members(t.current)
	if len(ms) == 0 {
		t.sys(t.current, "[gray]nobody has spoken yet. silent members are invisible by design.")
		return
	}
	for _, m := range ms {
		t.sys(t.current, "%s  [gray]last seen %s", renderNick(m.Nick, m.Fingerprint), m.LastSeen.Local().Format("15:04:05"))
	}
}

func (t *TUI) cmdWhois(q string) {
	if q == "" || !isChannel(t.current) {
		t.sys(t.current, "[red]usage: /whois <nick|fingerprint>  (inside a channel)")
		return
	}
	q = strings.ToLower(q)
	var hits int
	for _, m := range t.cli.Members(t.current) {
		if strings.ToLower(m.Nick) == q || strings.HasPrefix(m.Fingerprint, q) {
			hits++
			t.sys(t.current, "nick        [white]%s", tview.Escape(m.Nick))
			t.sys(t.current, "fingerprint [white]%s", m.Fingerprint)
			t.sys(t.current, "last seen   %s", m.LastSeen.Local().Format(time.RFC3339))
			t.sys(t.current, "[gray]that is everything anyone can know. there is no IP, no account, no metadata.")
		}
	}
	if hits == 0 {
		t.sys(t.current, "[gray]no match in this channel")
	}
	if hits > 1 {
		t.sys(t.current, "[red]%d identities share that nickname. trust the fingerprint, not the name.", hits)
	}
}

func (t *TUI) cmdWin(rest string) {
	n, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil || n < 1 || n > len(t.order) {
		t.sys(t.current, "[red]usage: /win <1-%d>", len(t.order))
		return
	}
	t.switchTo(t.order[n-1])
}

func (t *TUI) cmdHelp() {
	for _, l := range strings.Split(helpText, "\n") {
		t.sys(t.current, "%s", l)
	}
}

func (t *TUI) say(name, text string) {
	if !isChannel(name) {
		t.sys(t.current, "[gray]this is not a channel. /join #something first.")
		return
	}
	if err := t.cli.Say(name, text); err != nil {
		t.sys(t.current, "[red]%v", err)
	}
}

// ---- prompt ---------------------------------------------------------------

func (t *TUI) prompt(label string, done func(string)) {
	field := tview.NewInputField().
		SetLabel(label + ": ").
		SetMaskCharacter('*').
		SetFieldWidth(48)

	form := tview.NewForm().AddFormItem(field)
	form.SetBorder(true).SetTitle(" ghostwire ").SetTitleAlign(tview.AlignLeft)
	form.AddButton("ok", func() {
		v := field.GetText()
		t.pages.RemovePage("prompt")
		t.app.SetFocus(t.input)
		done(v)
	})
	form.AddButton("cancel", func() {
		t.pages.RemovePage("prompt")
		t.app.SetFocus(t.input)
	})

	t.pages.AddPage("prompt", center(form, 60, 7), true, true)
	t.app.SetFocus(field)
}

func center(p tview.Primitive, w, h int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, h, 0, true).
			AddItem(nil, 0, 1, false), w, 0, true).
		AddItem(nil, 0, 1, false)
}

// ---- buffers --------------------------------------------------------------

func (t *TUI) buf(name string) *buffer {
	if b, ok := t.bufs[name]; ok {
		return b
	}
	return t.bufs[statusBuffer]
}

func (t *TUI) ensure(name string) {
	if _, ok := t.bufs[name]; ok {
		return
	}
	t.bufs[name] = newBuffer(name)
	t.order = append(t.order, name)
	sort.SliceStable(t.order[1:], func(i, j int) bool { return t.order[1+i] < t.order[1+j] })
}

func (t *TUI) drop(name string) {
	delete(t.bufs, name)
	for i, n := range t.order {
		if n == name {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
	if t.current == name {
		t.switchTo(statusBuffer)
	}
}

func (t *TUI) bufferFor(channel string) string {
	if channel == "" {
		return statusBuffer
	}
	t.ensure(channel)
	return channel
}

func (t *TUI) line(name, format string, args ...any) {
	t.ensure(name)
	b := t.bufs[name]
	b.add(fmt.Sprintf(format, args...))
	if name != t.current {
		b.mu.Lock()
		b.unread++
		b.mu.Unlock()
	}
}

func (t *TUI) sys(name, format string, args ...any) { t.line(name, format, args...) }

func (t *TUI) switchTo(name string) {
	if _, ok := t.bufs[name]; !ok {
		return
	}
	t.current = name
	b := t.bufs[name]
	b.mu.Lock()
	b.unread = 0
	b.mu.Unlock()
	t.redraw()
}

func (t *TUI) cycle(delta int) {
	if len(t.order) == 0 {
		return
	}
	idx := 0
	for i, n := range t.order {
		if n == t.current {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(t.order)) % len(t.order)
	t.switchTo(t.order[idx])
	t.app.Draw()
}

func (t *TUI) redraw() {
	t.chat.SetTitle(fmt.Sprintf(" %s ", t.current))
	t.chat.SetText(strings.Join(t.buf(t.current).render(), "\n"))
	t.chat.ScrollToEnd()
	t.refresh()
}

func (t *TUI) refresh() {
	t.chat.SetTitle(fmt.Sprintf(" %s ", t.current))
	t.chat.SetText(strings.Join(t.buf(t.current).render(), "\n"))
	t.chat.ScrollToEnd()

	// roster
	var sb strings.Builder
	if isChannel(t.current) {
		ms := t.cli.Members(t.current)
		fmt.Fprintf(&sb, "[gray]%d heard[-]\n\n", len(ms))
		for _, m := range ms {
			marker := " "
			if m.Self {
				marker = "[white]•[-]"
			}
			fmt.Fprintf(&sb, "%s%s\n  [gray]%s[-]\n", marker, renderNick(m.Nick, m.Fingerprint), gcrypto.Short(m.Fingerprint))
		}
	} else {
		sb.WriteString("[gray]no channel[-]")
	}
	t.roster.SetText(sb.String())

	// status bar
	var parts []string
	for i, n := range t.order {
		label := fmt.Sprintf("%d:%s", i+1, n)
		b := t.bufs[n]
		b.mu.Lock()
		un := b.unread
		b.mu.Unlock()
		switch {
		case n == t.current:
			label = "[black:white]" + label + "[-:-]"
		case un > 0:
			label = fmt.Sprintf("[yellow]%s(%d)[-]", label, un)
		default:
			label = "[gray]" + label + "[-]"
		}
		parts = append(parts, label)
	}
	transport := "[green]tor[-]"
	if !t.viaTor {
		transport = "[red]clearnet[-]"
	}
	t.status.SetText(fmt.Sprintf(" %s  %s  [gray]%s[-]  %s",
		transport, strings.Join(parts, " "), gcrypto.Short(t.cli.Fingerprint()), tview.Escape(t.cli.Nick())))
}

// ---- helpers --------------------------------------------------------------

func isChannel(s string) bool { return strings.HasPrefix(s, "#") }

func renderNick(nick, fp string) string {
	if nick == "" {
		nick = "anon"
	}
	color := nickPalette[colorIndex(fp)]
	return fmt.Sprintf("[%s]%s[-][gray]#%s[-]", color, tview.Escape(nick), gcrypto.Short(fp))
}

func colorIndex(fp string) int {
	var sum int
	for i := 0; i < len(fp); i++ {
		sum = sum*31 + int(fp[i])
	}
	if sum < 0 {
		sum = -sum
	}
	return sum % len(nickPalette)
}

const bannerArt = `        __               __             _
  ___ _/ /  ___  ___ ___/ /_    __ __ __(_)______
 / _ ` + "`" + `/ _ \/ _ \(_-</ __/ |/|/ // // __/ -_)
 \_, /_//_/\___/___/\__/|__,__/ \_,_/_/  \___/
/___/                       no logs · no accounts · no you`

const helpText = `[white]channels[-]
  /join #room [pass]   derive a channel from name+passphrase and enter it
  /part [#room]        leave and destroy the channel key in RAM
  /msg #room <text>    speak into another window
  /me <text>           action line
  /names               who has actually spoken here
  /whois <nick|fp>     everything knowable about a member (it is not much)

[white]identity[-]
  /nick <name>         change the cosmetic label
  /keys                show your own fingerprint

[white]windows[-]
  /win <n>  /next  /prev      ^N  ^P    switch      ^L  clear

[white]exit[-]
  /quit                announce, close, exit
  /panic               wipe every key in memory and die immediately

[gray]there is no /list and no /topic. a server that could answer either
would be a server that knows what channels exist.[-]`
