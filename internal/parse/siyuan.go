package parse

import (
	"encoding/json"
	"fmt"
)

// SiYuanConfig captures only the persisted posture needed to determine
// whether an affected SiYuan kernel is exposing Publish anonymously.
type SiYuanConfig struct {
	System struct {
		KernelVersion string `json:"kernelVersion"`
	} `json:"system"`
	Publish struct {
		Enable bool `json:"enable"`
		Auth   struct {
			Enable bool `json:"enable"`
		} `json:"auth"`
	} `json:"publish"`
}

func parseSiYuanConfig(raw []byte) (*SiYuanConfig, error) {
	var cfg SiYuanConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("siyuan config parse: %w", err)
	}
	return &cfg, nil
}
