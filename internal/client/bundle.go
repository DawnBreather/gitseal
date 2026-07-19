package client

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseSource turns a plaintext source file (the thing a human edits) into a
// name→value map. format is "env", "json", or "yaml".
func ParseSource(data []byte, format string) (map[string]string, error) {
	switch format {
	case "env":
		return parseEnv(data)
	case "json":
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
		return m, nil
	case "yaml":
		var m map[string]string
		if err := yaml.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unknown source format %q (env|json|yaml)", format)
	}
}

func parseEnv(data []byte) (map[string]string, error) {
	m := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		// strip matching surrounding quotes
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if k != "" {
			m[k] = v
		}
	}
	return m, nil
}

// RenderSecrets serializes a name→value map back to the requested format, with
// stable key ordering.
func RenderSecrets(secrets map[string]string, format string) ([]byte, error) {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	switch format {
	case "env":
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%s\n", k, secrets[k])
		}
		return []byte(b.String()), nil
	case "json":
		// build an ordered object via a small manual encoder for stable output
		ordered := make(map[string]string, len(secrets))
		for k, v := range secrets {
			ordered[k] = v
		}
		out, err := json.MarshalIndent(ordered, "", "  ")
		return out, err
	case "yaml":
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s: %s\n", k, secrets[k])
		}
		return []byte(b.String()), nil
	default:
		return nil, fmt.Errorf("unknown output format %q (env|json|yaml)", format)
	}
}

// FormatFromPath guesses the format from a file extension.
func FormatFromPath(path string) string {
	switch {
	case strings.HasSuffix(path, ".env") || strings.HasSuffix(path, ".envrc"):
		return "env"
	case strings.HasSuffix(path, ".json"):
		return "json"
	case strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml"):
		return "yaml"
	default:
		return "env"
	}
}

// NameDiff is a name-level (not value-level) diff between two bundles. Values
// can't be diffed: sealing is non-deterministic and seeing old values would
// require decryption (broker + membership), breaking offline-seal.
type NameDiff struct {
	Added   []string
	Removed []string
	Kept    []string
}

// DiffNames computes which names were added, removed, or kept between old→new.
func DiffNames(oldNames, newNames []string) NameDiff {
	oldSet := map[string]bool{}
	for _, n := range oldNames {
		oldSet[n] = true
	}
	newSet := map[string]bool{}
	for _, n := range newNames {
		newSet[n] = true
	}
	var d NameDiff
	for _, n := range newNames {
		if oldSet[n] {
			d.Kept = append(d.Kept, n)
		} else {
			d.Added = append(d.Added, n)
		}
	}
	for _, n := range oldNames {
		if !newSet[n] {
			d.Removed = append(d.Removed, n)
		}
	}
	return d
}
