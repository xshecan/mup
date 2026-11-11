package config

import (
	"fmt"
	"os"

	uberconfig "go.uber.org/config"
)

// Load reads a YAML configuration file. Values can use ${VARIABLE} and
// ${VARIABLE:default}. An unknown key is an error.
func Load(path string) (App, error) {
	provider, err := uberconfig.NewYAML(uberconfig.File(path), uberconfig.Expand(os.LookupEnv))
	if err != nil {
		return App{}, fmt.Errorf("read configuration file: %w", err)
	}
	var app App
	if err := provider.Get(uberconfig.Root).Populate(&app); err != nil {
		return App{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := app.Validate(); err != nil {
		return App{}, fmt.Errorf("%s: %w", path, err)
	}
	return app, nil
}
