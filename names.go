package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// The approval page names the vaults and items a command refers to by ID, from
// a snapshot of everything the service account can read. A snapshot is reused
// for namesTTL. An ID it lacks, or a failed refresh, waits namesRetry before
// another refresh, so a stream of bad IDs or a rate limit can't spend calls.
const (
	namesTTL   = 10 * time.Minute
	namesRetry = 30 * time.Second
	namesWait  = 5 * time.Second // how long the page waits on a refresh
)

const namesFailed = "Couldn't look up names."

var opID = regexp.MustCompile(`^[a-z0-9]{26}$`)

// itemRef is an item ID in a command, with the vault the command names for
// it, by ID or name; "" if none.
type itemRef struct{ id, vault string }

// refs are the vault and item IDs in a command's arguments, each listed once.
// Names aren't refs: the page already shows them as typed.
type refs struct {
	vaults []string
	items  []itemRef
}

func (r refs) count() int { return len(r.vaults) + len(r.items) }

func (r *refs) addVault(id string) {
	if !slices.Contains(r.vaults, id) {
		r.vaults = append(r.vaults, id)
	}
}

func (r *refs) addItem(it itemRef) {
	if !slices.Contains(r.items, it) {
		r.items = append(r.items, it)
	}
}

func findRefs(args []string) refs {
	var r refs
	var vault string
	var bare []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--vault" && i+1 < len(args):
			i++
			vault = args[i]
		case strings.HasPrefix(a, "--vault="):
			vault = strings.TrimPrefix(a, "--vault=")
		case strings.HasPrefix(a, "op://"):
			seg := strings.SplitN(strings.TrimPrefix(a, "op://"), "/", 3)
			if opID.MatchString(seg[0]) {
				r.addVault(seg[0])
			}
			if len(seg) > 1 && opID.MatchString(seg[1]) {
				r.addItem(itemRef{seg[1], seg[0]})
			}
		// shortcut: any ID-shaped argument counts, even a name of that shape or
		// another flag's value (--account <id>); telling them apart needs op's
		// flag table and a lookup by name. Such a value reads as not found.
		case opID.MatchString(a):
			bare = append(bare, a)
		}
	}
	if opID.MatchString(vault) {
		r.addVault(vault)
	}
	for _, id := range bare {
		switch args[0] {
		case "vault":
			r.addVault(id)
		case "item", "document":
			r.addItem(itemRef{id, vault})
		}
	}
	return r
}

type itemEntry struct {
	title string
	vault string // vault ID
}

// snapshot maps the IDs the service account can read to names.
type snapshot struct {
	vaults map[string]string // vault ID -> name
	items  map[string]itemEntry
}

// vaultLine is vault id's line on the approval page, and whether s knows id.
func (s snapshot) vaultLine(id string) (string, bool) {
	if name, ok := s.vaults[id]; ok {
		return "vault " + id[:8] + " = " + name, true
	}
	return "vault " + id[:8] + " not found", false
}

// itemLine is r's line on the approval page, and whether s knows r's ID. An
// item counts as found only in the vault the command names, as op matches it.
func (s snapshot) itemLine(r itemRef) (string, bool) {
	head := "item " + r.id[:8]
	it, ok := s.items[r.id]
	switch {
	case !ok:
		return head + " not found", false
	case r.vault != "" && r.vault != it.vault && !strings.EqualFold(r.vault, s.vaults[it.vault]):
		return head + " not found in " + s.vaultLabel(r.vault), true
	}
	return head + " = " + it.title, true
}

// vaultLabel names a vault given by ID or name, as briefly as the page can.
func (s snapshot) vaultLabel(v string) string {
	if name, ok := s.vaults[v]; ok {
		return name
	}
	if opID.MatchString(v) {
		return "vault " + v[:8]
	}
	return v
}

// missing reports whether r has an ID s doesn't know.
func (s snapshot) missing(r refs) bool {
	for _, id := range r.vaults {
		if _, ok := s.vaults[id]; !ok {
			return true
		}
	}
	for _, it := range r.items {
		if _, ok := s.items[it.id]; !ok {
			return true
		}
	}
	return false
}

// needsRefresh decides whether to fetch a new snapshot, given the time since
// the last attempt, whether it failed, and whether the IDs wanted are missing.
func needsRefresh(age time.Duration, failed, missing bool) bool {
	switch {
	case age >= namesTTL:
		return true
	case age < namesRetry:
		return false
	default:
		return failed || missing
	}
}

// names caches the snapshot. A nil *names looks nothing up.
type names struct {
	list func(context.Context) (snapshot, error)

	mu    sync.Mutex
	snap  snapshot  // the last good snapshot
	err   error     // the last attempt's error
	at    time.Time // the last attempt; zero means never
	group singleflight.Group
}

// lines describes each vault and item ID in args for request id's page. When
// the lookup failed, it describes what the last good snapshot knows, and adds
// namesFailed in place of the rest.
func (n *names) lines(ctx context.Context, id string, args []string) []string {
	rs := findRefs(args)
	if n == nil || rs.count() == 0 {
		return nil
	}
	ctx, span := tracer.Start(ctx, "op_gate.names")
	defer span.End()

	s, refreshed, err := n.get(ctx, id, rs)
	var out []string
	unknown := 0
	add := func(line string, known bool) {
		if !known {
			unknown++
			if err != nil {
				return
			}
		}
		out = append(out, line)
	}
	for _, v := range rs.vaults {
		add(s.vaultLine(v))
	}
	for _, it := range rs.items {
		add(s.itemLine(it))
	}
	if err != nil && unknown > 0 {
		out = append(out, namesFailed)
	}

	span.SetAttributes(
		attribute.String("op_gate.request_id", id),
		attribute.Int("op_gate.names.refs", rs.count()),
		attribute.Int("op_gate.names.unknown", unknown),
		attribute.Bool("op_gate.names.refreshed", refreshed),
	)
	if err != nil {
		span.SetStatus(codes.Error, "name lookup failed")
	}
	return out
}

// get returns the snapshot to describe rs with, whether this call waited on a
// refresh, and the last attempt's error. Concurrent callers share one refresh,
// which outlives a caller that gives up. A failed refresh keeps the last good
// snapshot.
func (n *names) get(ctx context.Context, id string, rs refs) (snapshot, bool, error) {
	n.mu.Lock()
	s, err, at := n.snap, n.err, n.at
	n.mu.Unlock()
	if !needsRefresh(time.Since(at), err != nil, s.missing(rs)) {
		return s, false, err
	}

	ch := n.group.DoChan("", func() (any, error) {
		fresh, err := n.list(context.WithoutCancel(ctx))
		if err != nil {
			slog.WarnContext(ctx, "looking up names", "request_id", id, "err", err)
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if err == nil {
			n.snap = fresh
		}
		n.err, n.at = err, time.Now()
		return n.snap, err
	})
	select {
	case r := <-ch:
		return r.Val.(snapshot), true, r.Err
	case <-ctx.Done():
		return s, true, ctx.Err()
	}
}

// listNames reads the ID and name of every vault and item the service account
// can read. It runs only list commands: op item get would return field values,
// putting secrets in op-gate's memory before anyone approved them.
func listNames(ctx context.Context, run func(context.Context, []string) result) (snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var vaults []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var items []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Vault struct {
			ID string `json:"id"`
		} `json:"vault"`
	}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return opJSON(gctx, run, &vaults, "vault", "list") })
	g.Go(func() error { return opJSON(gctx, run, &items, "item", "list") })
	if err := g.Wait(); err != nil {
		return snapshot{}, err
	}

	s := snapshot{vaults: make(map[string]string, len(vaults)), items: make(map[string]itemEntry, len(items))}
	for _, v := range vaults {
		s.vaults[v.ID] = v.Name
	}
	for _, it := range items {
		s.items[it.ID] = itemEntry{title: it.Title, vault: it.Vault.ID}
	}
	return s, nil
}

// opJSON runs op with args and --format json, and decodes its output into v.
func opJSON(ctx context.Context, run func(context.Context, []string) result, v any, args ...string) error {
	res := run(ctx, append(args, "--format", "json"))
	if res.ExitCode != 0 {
		return fmt.Errorf("op %s: %s", strings.Join(args, " "), strings.TrimSpace(res.Stderr))
	}
	if err := json.Unmarshal([]byte(res.Stdout), v); err != nil {
		return fmt.Errorf("op %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
