// Package client implements the sealdctl laptop-side logic: resolving the
// developer's existing GitLab PAT, sealing offline, and calling the broker.
package client

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// ResolvePAT returns the developer's GitLab PAT for host, trying in order:
//  1. $GITLAB_TOKEN
//  2. `glab auth token --hostname <host>`
//  3. the glab config file (configPath; if "", the default location)
//
// It never prompts and never writes the token anywhere. Returns (token, source).
func ResolvePAT(host, configPath string) (token, source string, err error) {
	if t := strings.TrimSpace(os.Getenv("GITLAB_TOKEN")); t != "" {
		return t, "env", nil
	}
	// `glab auth token` (best-effort; ignored if glab absent or errors)
	if out, e := exec.Command("glab", "auth", "token", "--hostname", host).Output(); e == nil {
		if t := strings.TrimSpace(string(out)); t != "" {
			return t, "glab", nil
		}
	}
	// glab config file
	if configPath == "" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			configPath = xdg + "/glab-cli/config.yml"
		} else {
			configPath = os.Getenv("HOME") + "/.config/glab-cli/config.yml"
		}
	}
	if t, e := tokenFromGlabConfig(configPath, host); e == nil && t != "" {
		return t, "glab-config", nil
	}
	return "", "", fmt.Errorf("no GitLab token found for %s (set $GITLAB_TOKEN or run `glab auth login`)", host)
}

func tokenFromGlabConfig(path, host string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Hosts map[string]struct {
			Token string `yaml:"token"`
		} `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	h, ok := cfg.Hosts[host]
	if !ok || h.Token == "" {
		return "", fmt.Errorf("no token for host %s in %s", host, path)
	}
	return h.Token, nil
}
