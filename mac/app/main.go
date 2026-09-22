package main

import (
	"context"
	"embed"
	"sync/atomic"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"k10webprotection/internal/config"
	"k10webprotection/internal/i18n"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Resolve the UI language before the window is created.
	i18n.SetLang(config.Load().Language)

	app := NewApp()

	err := wails.Run(&options.App{
		Title:         i18n.T("app.title"),
		Width:         960,
		Height:        660,
		MinWidth:      960,
		MinHeight:     660,
		MaxWidth:      960,
		MaxHeight:     660,
		DisableResize: true,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 10, G: 22, B: 40, A: 255},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		OnBeforeClose: func(ctx context.Context) bool {
			// Allow immediate quit during macOS shutdown/restart/logout,
			// or when the user has already confirmed with their password.
			if systemShuttingDown() || atomic.LoadInt32(&app.quitAuth) == 1 {
				return false
			}
			wailsruntime.EventsEmit(ctx, "quit-requested")
			return true // block close; frontend handles via modal
		},
		Bind:             []interface{}{app},
		Mac: &mac.Options{
			TitleBar: &mac.TitleBar{
				TitlebarAppearsTransparent: true,
				HideTitle:                  true,
				HideTitleBar:               false,
				FullSizeContent:            true,
				UseToolbar:                 false,
			},
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "com.k10webprotection.app",
			OnSecondInstanceLaunch: func(data options.SecondInstanceData) {
				wailsruntime.WindowShow(app.ctx)
				wailsruntime.WindowUnminimise(app.ctx)
			},
		},
	})
	if err != nil {
		panic(err)
	}
}
