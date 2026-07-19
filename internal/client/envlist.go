package client

import (
	"fmt"
	"sort"
	"strings"
)

// RenderEnvList formats a resolved RepoConfig into a table of the project's
// environments (`sealdctl env list`): each env → its cluster, the GitLab
// access level required to change its secrets, and whether the caller can seal it.
//
// callerLevel is the caller's LIVE effective project level; pass -1 for "unknown"
// (couldn't resolve — offline, no token) so the WRITE column shows "?" instead of
// a misleading ✓/✗. The env config comes from the broker registry snapshot (this
// is a pure formatter over the already-resolved RepoConfig).
func RenderEnvList(rc *RepoConfig, callerLevel int) string {
	envs := make([]string, 0, len(rc.EnvCluster))
	for e := range rc.EnvCluster {
		envs = append(envs, e)
	}
	sort.Strings(envs)

	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-14s %-9s %s\n", "ENV", "CLUSTER", "MIN-LVL", writeHeader(callerLevel))
	for _, e := range envs {
		min := rc.MinLevelForEnv(e)
		fmt.Fprintf(&b, "%-10s %-14s %-9d %s\n", e, rc.EnvCluster[e], min, writeCell(callerLevel, min))
	}
	return b.String()
}

func writeHeader(callerLevel int) string {
	if callerLevel < 0 {
		return "YOU (level ?)"
	}
	return fmt.Sprintf("YOU (level %d)", callerLevel)
}

func writeCell(callerLevel, min int) string {
	if callerLevel < 0 {
		return "? unknown"
	}
	if callerLevel >= min {
		return "✓ can seal"
	}
	return "✗ read-only"
}
