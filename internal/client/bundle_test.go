package client

import (
	"reflect"
	"sort"
	"testing"
)

// --- format readers: parse a plaintext source file into name→value ----------

func TestParseEnvFormat(t *testing.T) {
	src := []byte("# comment\nDATABASE_URL=postgres://db\nAPI_KEY = sk-123 \n\nexport REDIS=redis://x\n")
	got, err := ParseSource(src, "env")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"DATABASE_URL": "postgres://db", "API_KEY": "sk-123", "REDIS": "redis://x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env parse: got %v want %v", got, want)
	}
}

func TestParseJSONFormat(t *testing.T) {
	src := []byte(`{"DATABASE_URL":"postgres://db","API_KEY":"sk-123"}`)
	got, err := ParseSource(src, "json")
	if err != nil {
		t.Fatal(err)
	}
	if got["DATABASE_URL"] != "postgres://db" || got["API_KEY"] != "sk-123" {
		t.Fatalf("json parse: %v", got)
	}
}

func TestParseYAMLFormat(t *testing.T) {
	src := []byte("DATABASE_URL: postgres://db\nAPI_KEY: sk-123\n")
	got, err := ParseSource(src, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got["DATABASE_URL"] != "postgres://db" || got["API_KEY"] != "sk-123" {
		t.Fatalf("yaml parse: %v", got)
	}
}

func TestParseFormatDetectByExtension(t *testing.T) {
	if FormatFromPath("prod.env") != "env" ||
		FormatFromPath("prod.json") != "json" ||
		FormatFromPath("prod.yaml") != "yaml" ||
		FormatFromPath("prod.yml") != "yaml" {
		t.Fatal("extension detection wrong")
	}
}

// --- format writers: render name→value back out -----------------------------

func TestRenderEnv(t *testing.T) {
	out, err := RenderSecrets(map[string]string{"B": "2", "A": "1"}, "env")
	if err != nil {
		t.Fatal(err)
	}
	// keys sorted for stable output
	if string(out) != "A=1\nB=2\n" {
		t.Fatalf("env render: %q", out)
	}
}

func TestRenderJSON(t *testing.T) {
	out, err := RenderSecrets(map[string]string{"A": "1"}, "json")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "{\n  \"A\": \"1\"\n}" && string(out) != "{\n  \"A\": \"1\"\n}\n" {
		t.Fatalf("json render: %q", out)
	}
}

// --- bundle diff (name-level: added / removed / kept) ------------------------

func TestBundleDiffNameLevel(t *testing.T) {
	oldNames := []string{"A", "B", "C"}
	newNames := []string{"B", "C", "D"}
	d := DiffNames(oldNames, newNames)
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Kept)
	if !reflect.DeepEqual(d.Added, []string{"D"}) {
		t.Fatalf("added: %v", d.Added)
	}
	if !reflect.DeepEqual(d.Removed, []string{"A"}) {
		t.Fatalf("removed: %v", d.Removed)
	}
	if !reflect.DeepEqual(d.Kept, []string{"B", "C"}) {
		t.Fatalf("kept: %v", d.Kept)
	}
}
