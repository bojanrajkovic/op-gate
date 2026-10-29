package main

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// opid pads p to the shape of a 1Password ID.
func opid(p string) string { return p + strings.Repeat("0", 26-len(p)) }

var (
	agentsID = opid("agents")
	otherID  = opid("private")
	githubID = opid("github")
	unknown  = opid("unknown")
)

var testSnapshot = snapshot{
	vaults: map[string]string{agentsID: "Agents", otherID: "Private"},
	items:  map[string]itemEntry{githubID: {title: "GitHub Token", vault: agentsID}},
}

func TestFindRefs(t *testing.T) {
	gh := func(vault string) []itemRef { return []itemRef{{githubID, vault}} }
	tests := []struct {
		args []string
		want refs
	}{
		{[]string{"read", "op://" + agentsID + "/" + githubID + "/credential"}, refs{[]string{agentsID}, gh(agentsID)}},
		{[]string{"read", "op://Agents/" + githubID + "/section/field?attribute=otp"}, refs{nil, gh("Agents")}},
		{[]string{"read", "op://Agents/GitHub Token/credential"}, refs{}},
		{[]string{"item", "get", githubID, "--vault", agentsID}, refs{[]string{agentsID}, gh(agentsID)}},
		{[]string{"item", "get", githubID, "--vault=Agents", "--format", "json"}, refs{nil, gh("Agents")}},
		{[]string{"document", "get", githubID}, refs{nil, gh("")}},
		{[]string{"vault", "get", agentsID}, refs{[]string{agentsID}, nil}},
		{[]string{"vault", "get", agentsID, "--vault", agentsID}, refs{[]string{agentsID}, nil}}, // listed once
		{[]string{"item", "list", "--vault", agentsID}, refs{[]string{agentsID}, nil}},
		{[]string{"read", githubID}, refs{}}, // not a reference, so not an item
		{[]string{"whoami"}, refs{}},
	}
	for _, tt := range tests {
		if got := findRefs(tt.args); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("findRefs(%q) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestSnapshotLines(t *testing.T) {
	vaults := []struct {
		id   string
		want string
	}{
		{agentsID, "vault agents00 = Agents"},
		{unknown, "vault unknown0 not found"},
	}
	for _, tt := range vaults {
		if got := testSnapshot.vaultLine(tt.id); got != tt.want {
			t.Errorf("vaultLine(%s) = %q", tt.id, got)
		}
	}
	items := []struct {
		r    itemRef
		want string
	}{
		{itemRef{githubID, ""}, "item github00 = GitHub Token"},
		{itemRef{githubID, agentsID}, "item github00 = GitHub Token"},
		{itemRef{githubID, "agents"}, "item github00 = GitHub Token"},
		{itemRef{githubID, otherID}, "item github00 not found in Private"},
		{itemRef{githubID, unknown}, "item github00 not found in vault unknown0"},
		{itemRef{githubID, "Nope"}, "item github00 not found in Nope"},
		{itemRef{unknown, ""}, "item unknown0 not found"},
	}
	for _, tt := range items {
		if got := testSnapshot.itemLine(tt.r); got != tt.want {
			t.Errorf("itemLine(%v) = %q", tt.r, got)
		}
	}
}

func TestDescribeRefs(t *testing.T) {
	rs := refs{[]string{agentsID, unknown}, []itemRef{{githubID, otherID}, {unknown, ""}}}
	tests := []struct {
		failed      bool
		want        []string
		wantUnknown int
	}{
		{false, []string{"vault agents00 = Agents", "vault unknown0 not found",
			"item github00 not found in Private", "item unknown0 not found"}, 2},
		// After a failure, the unknown IDs may just be new, so they don't read as not found.
		{true, []string{"vault agents00 = Agents", "item github00 not found in Private", namesFailed}, 2},
	}
	for _, tt := range tests {
		if got, unknown := describeRefs(testSnapshot, rs, tt.failed); !slices.Equal(got, tt.want) || unknown != tt.wantUnknown {
			t.Errorf("describeRefs(failed=%v) = %q, %d", tt.failed, got, unknown)
		}
	}
	if got, _ := describeRefs(snapshot{}, refs{vaults: []string{agentsID}}, true); !slices.Equal(got, []string{namesFailed}) {
		t.Errorf("first lookup failed: %q", got)
	}
}

func TestNeedsRefresh(t *testing.T) {
	tests := []struct {
		age             time.Duration
		failed, missing bool
		want            bool
	}{
		{time.Minute, false, false, false},
		{namesTTL, false, false, true},
		{10 * time.Second, false, true, false}, // a miss right after a refresh waits
		{namesRetry, false, true, true},
		{10 * time.Second, true, false, false}, // a failure right after a refresh waits
		{namesRetry, true, false, true},
	}
	for _, tt := range tests {
		if got := needsRefresh(tt.age, tt.failed, tt.missing); got != tt.want {
			t.Errorf("needsRefresh(%v, failed=%v, missing=%v) = %v", tt.age, tt.failed, tt.missing, got)
		}
	}
}

// countingNames returns a nameCache whose list answers with list and counts its calls.
func countingNames(list func() (snapshot, error)) (*nameCache, *int) {
	calls := new(int)
	return &nameCache{list: func(context.Context) (snapshot, error) {
		*calls++
		return list()
	}}, calls
}

func TestNameCacheDescribe(t *testing.T) {
	known := []string{"read", "op://" + agentsID + "/" + githubID + "/credential"}
	missing := []string{"read", "op://" + agentsID + "/" + unknown + "/credential"}
	ok := func() (snapshot, error) { return testSnapshot, nil }

	t.Run("refreshes after the TTL", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			n, calls := countingNames(ok)
			want := []string{"vault agents00 = Agents", "item github00 = GitHub Token"}
			if got := n.describe(t.Context(), "req1", known); !slices.Equal(got, want) {
				t.Fatalf("lines = %q", got)
			}
			time.Sleep(namesTTL - time.Second)
			n.describe(t.Context(), "req2", known)
			if *calls != 1 {
				t.Fatalf("calls within the TTL = %d", *calls)
			}
			time.Sleep(time.Second)
			n.describe(t.Context(), "req3", known)
			if *calls != 2 {
				t.Fatalf("calls after the TTL = %d", *calls)
			}
		})
	})

	t.Run("a miss refreshes at most every 30s", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			n, calls := countingNames(ok)
			n.describe(t.Context(), "req1", missing)
			n.describe(t.Context(), "req2", missing)
			if *calls != 1 {
				t.Fatalf("calls = %d", *calls)
			}
			time.Sleep(namesRetry)
			n.describe(t.Context(), "req3", missing)
			if *calls != 2 {
				t.Fatalf("calls after 30s = %d", *calls)
			}
		})
	})

	t.Run("a failure is remembered for 30s", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			n, calls := countingNames(func() (snapshot, error) { return snapshot{}, errors.New("rate limited") })
			for _, id := range []string{"req1", "req2"} {
				if got := n.describe(t.Context(), id, known); !slices.Equal(got, []string{namesFailed}) {
					t.Fatalf("lines = %q", got)
				}
			}
			if *calls != 1 {
				t.Fatalf("calls = %d; a failure must not retry right away", *calls)
			}
			time.Sleep(namesRetry)
			n.describe(t.Context(), "req3", known)
			if *calls != 2 {
				t.Fatalf("calls after 30s = %d", *calls)
			}
		})
	})

	t.Run("a failed refresh keeps the last good names", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fail := false
			n, _ := countingNames(func() (snapshot, error) {
				if fail {
					return snapshot{}, errors.New("rate limited")
				}
				return testSnapshot, nil
			})
			n.describe(t.Context(), "req1", known)
			fail = true
			time.Sleep(namesTTL)
			if got := n.describe(t.Context(), "req2", known); !slices.Equal(got, []string{"vault agents00 = Agents", "item github00 = GitHub Token"}) {
				t.Fatalf("known IDs = %q", got)
			}
			if got := n.describe(t.Context(), "req3", missing); !slices.Equal(got, []string{"vault agents00 = Agents", namesFailed}) {
				t.Fatalf("an unknown ID = %q", got)
			}
		})
	})

	t.Run("a caller that gives up doesn't cancel the refresh", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			n, calls := countingNames(func() (snapshot, error) {
				time.Sleep(10 * time.Second)
				return testSnapshot, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), namesWait)
			defer cancel()
			if got := n.describe(ctx, "req1", known); !slices.Equal(got, []string{namesFailed}) {
				t.Fatalf("lines = %q", got)
			}
			time.Sleep(10 * time.Second)
			if got := n.describe(t.Context(), "req2", known); len(got) != 2 || *calls != 1 {
				t.Fatalf("lines = %q after %d calls", got, *calls)
			}
		})
	})

	t.Run("commands without IDs look nothing up", func(t *testing.T) {
		n, calls := countingNames(ok)
		if got := n.describe(t.Context(), "req1", []string{"read", "op://Agents/GitHub Token/credential"}); got != nil || *calls != 0 {
			t.Fatalf("lines = %q after %d calls", got, *calls)
		}
	})

	t.Run("nil names is a no-op", func(t *testing.T) {
		if got := (*nameCache)(nil).describe(t.Context(), "req1", known); got != nil {
			t.Fatalf("lines = %q", got)
		}
	})
}

func TestListNames(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var ran []string
		run := func(_ context.Context, args []string) result {
			mu.Lock()
			ran = append(ran, strings.Join(args, " "))
			mu.Unlock()
			time.Sleep(time.Second)
			switch args[0] {
			case "vault":
				return result{Stdout: `[{"id":"` + agentsID + `","name":"Agents","items":1},{"id":"` + otherID + `","name":"Private"}]`}
			default:
				return result{Stdout: `[{"id":"` + githubID + `","title":"GitHub Token","category":"LOGIN",` +
					`"additional_information":"someone","vault":{"id":"` + agentsID + `","name":"Agents"}}]`}
			}
		}
		start := time.Now()
		s, err := listNames(t.Context(), run)
		if err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took != time.Second {
			t.Errorf("listing took %v; the two calls should run at once", took)
		}
		if line := s.itemLine(itemRef{githubID, "Agents"}); line != "item github00 = GitHub Token" || s.vaults[otherID] != "Private" {
			t.Fatalf("snapshot = %+v", s)
		}
		slices.Sort(ran)
		if want := []string{"item list --format json", "vault list --format json"}; !slices.Equal(ran, want) {
			t.Fatalf("ran %q; only list commands may run, since item get returns field values", ran)
		}
	})

	failing := func(context.Context, []string) result { return result{Stderr: "rate limit exceeded\n", ExitCode: 1} }
	if _, err := listNames(t.Context(), failing); err == nil || !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("err = %v", err)
	}
}
