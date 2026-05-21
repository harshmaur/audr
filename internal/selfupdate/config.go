package selfupdate

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const ConfigFilename = "update.config.json"

type Config struct {
	AutoUpdate bool   `json:"auto_update"`
	Channel    string `json:"channel"`
}

func DefaultConfig() Config {
	return Config{AutoUpdate: false, Channel: "stable"}
}

func ConfigPath(stateDir string) string {
	return filepath.Join(stateDir, ConfigFilename)
}

func LoadConfig(stateDir string) (Config, error) {
	cfg := DefaultConfig()
	b, err := os.ReadFile(ConfigPath(stateDir))
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Channel == "" {
		cfg.Channel = "stable"
	}
	return cfg, nil
}

func SaveConfig(stateDir string, cfg Config) error {
	if cfg.Channel == "" {
		cfg.Channel = "stable"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := ConfigPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ConfigPath(stateDir))
}
