//go:build windows

package tray

import (
	"context"
	_ "embed"

	"github.com/energye/systray"
)

//go:embed icon.ico
var icon []byte // placeholder icon (bchs_favicon.ico) pending the real K10 logo

// Run starts the tray icon in the background and blocks until ctx is done.
func Run(ctx context.Context, onOpen func(), onExit func()) {
	go systray.Run(func() {
		systray.SetIcon(icon)
		systray.SetTitle("K10 Web Protection")
		systray.SetTooltip("K10 Web Protection")

		mOpen := systray.AddMenuItem("Open K10 Web Protection", "Open K10 Web Protection")
		systray.AddSeparator()
		mExit := systray.AddMenuItem("Exit", "Exit K10 Web Protection")

		mOpen.Click(onOpen)
		mExit.Click(onExit)
		systray.SetOnClick(func(_ systray.IMenu) { onOpen() })
		systray.SetOnDClick(func(_ systray.IMenu) { onOpen() })
	}, func() {})

	go func() {
		<-ctx.Done()
		Stop()
	}()
}

// Stop removes the tray icon so no orphan icon is left behind on exit.
func Stop() {
	systray.Quit()
}
