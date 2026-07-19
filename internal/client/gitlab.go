package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CallerHasLevel reports whether the caller (by their PAT) currently has
// >= level on the project, via GitLab's effective-permission endpoint. This is
// used ONLY for the advisory courtesy warning in `seal --from`; it is NOT an
// enforcement boundary (the real write gate is GitLab merge controls on the
// bundle path —). A transport error returns (false, err).
func CallerHasLevel(host, token string, projectID int64, level int) (bool, error) {
	url := fmt.Sprintf("https://%s/api/v4/projects/%d?min_access_level=%d", host, projectID, level)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// NOTE: GitLabUserHasKey (used by the removed `admin onboard-user`) was deleted in
// — user identity is now derived by the broker's GitLab-backed index, not
// verified at a manual onboarding step.

// ProjectMemberLevel returns the EFFECTIVE numeric access level of user userID on
// the project (including inherited group membership), via
// GET /projects/:id/members/all/:user_id against https://<host>. 404 → 0 (not a
// member). A transport error or any non-200/404 status returns an error so the
// caller can FAIL CLOSED (treat as unauthorized).
//
// This deliberately uses members/all/:user_id — NOT ?min_access_level=N — because
// (broker lesson) that query param does NOT gate on this GitLab version (returns
// 200 even below the level). members/all returns the authoritative numeric level,
// which the write-authz verdict compares itself. This is the write-side twin of
// the broker's read-side callerLevel.
func ProjectMemberLevel(host, token string, projectID, userID int64) (int, error) {
	return ProjectMemberLevelAt("https://"+host, token, projectID, userID)
}

// ProjectMemberLevelAt is ProjectMemberLevel with an explicit base URL (scheme +
// host, no trailing slash) — used by tests (httptest) and any non-default host.
func ProjectMemberLevelAt(baseURL, token string, projectID, userID int64) (int, error) {
	url := fmt.Sprintf("%s/api/v4/projects/%d/members/all/%d", baseURL, projectID, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return 0, nil // not a member
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("members/all returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	var m struct {
		AccessLevel int `json:"access_level"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return 0, fmt.Errorf("parse member: %w", err)
	}
	return m.AccessLevel, nil
}

// CallerProjectLevel resolves the caller's OWN effective access level on a project
// (for `env list`'s can-seal column): GET /user → the caller's user id, then
// members/all/:id for the authoritative numeric level. A non-member is level 0
// (not an error). Used read-only + best-effort — the caller falls back to
// "unknown" (-1) if this errors (no token / offline).
func CallerProjectLevel(host, token string, projectID int64) (int, error) {
	return callerProjectLevelAt("https://"+host, token, projectID)
}

func callerProjectLevelAt(baseURL, token string, projectID int64) (int, error) {
	req, err := http.NewRequest("GET", baseURL+"/api/v4/user", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("/user returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	var u struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &u); err != nil || u.ID == 0 {
		return 0, fmt.Errorf("resolve caller user id: %w", err)
	}
	return ProjectMemberLevelAt(baseURL, token, projectID, u.ID)
}
