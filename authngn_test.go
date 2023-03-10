package authngn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testtype struct {
	id    string
	owner string
}

func TestAuthorize(t *testing.T) {
	ngn := New()
	ngn.Register(testtype{}, "read", testtype{}, func(ent, res any) bool {
		ttEnt := ent.(testtype)
		ttRes := res.(testtype)
		return ttEnt.id == ttRes.owner
	})
	ngn.Register("", "read,write,delete", testtype{}, func(ent, res any) bool {
		ttRes := res.(testtype)
		return ent == ttRes.owner
	})

	id := "123465-abcdef"
	testcases := []struct {
		ent    any
		action string
		res    any
		result bool
	}{
		// Test single actions
		{testtype{id: id}, "read", testtype{owner: id}, true},
		{testtype{id: id}, "read", testtype{owner: "not-id"}, false},
		{"aoeusnth", "read", testtype{owner: "aoeusnth"}, true},
		{"aoeusnt", "read", testtype{owner: "aoeusnth"}, false},
		{"aoeusnth", "write", testtype{owner: "aoeusnth"}, true},
		{"aoeusnt", "write", testtype{owner: "aoeusnth"}, false},
		{"aoeusnth", "delete", testtype{owner: "aoeusnth"}, true},
		{"aoeusnt", "delete", testtype{owner: "aoeusnth"}, false},
		{123, "write", "aoeusnth", false},
		{testtype{id: id}, "create", testtype{owner: id}, false},

		// Test set of actions
		{"aoeusnth", "read,write,delete", testtype{owner: "aoeusnth"}, true},
		{"aoeusnt", "read,write,delete", testtype{owner: "aoeusnth"}, false},
		{"aoeusnth", "read,write,execute", testtype{owner: "aoeusnth"}, false},
	}

	for i, tc := range testcases {
		assert.Equal(t,
			tc.result,
			ngn.Authorize(tc.ent, tc.action, tc.res),
			"failed on test case %d", i)
	}
}

func TestContains(t *testing.T) {
	ngn := New()
	require.False(t, ngn.Contains(testtype{}, "read", ""))
	require.False(t, ngn.Contains(testtype{}, "write", ""))
	require.False(t, ngn.Contains(testtype{}, "delete", ""))

	ngn.Register(&testtype{}, "delete", "", func(_, _ any) bool {
		return true
	})

	require.False(t, ngn.Contains(testtype{}, "read", ""))
	require.False(t, ngn.Contains(testtype{}, "write", ""))
	require.True(t, ngn.Contains(testtype{}, "delete", ""))

	ngn.Register(&testtype{}, "read,write", testtype{}, func(_, _ any) bool {
		return true
	})

	require.True(t, ngn.Contains(testtype{}, "read", testtype{}))
	require.True(t, ngn.Contains(testtype{}, "write", testtype{}))
	require.False(t, ngn.Contains(testtype{}, "delete", testtype{}))
}

func TestDelete(t *testing.T) {
	ngn := New()

	ngn.Register(testtype{}, "execute", testtype{}, func(_, _ any) bool {
		return true
	})
	require.True(t, ngn.Authorize(testtype{}, "execute", testtype{}))

	ngn.Delete(testtype{}, "execute", testtype{})
	require.False(t, ngn.Authorize(testtype{}, "execute", testtype{}))

	ngn.Register(testtype{}, "read,write,delete", testtype{}, func(_, _ any) bool {
		return true
	})
	require.True(t, ngn.Authorize(testtype{}, "read", testtype{}))
	require.True(t, ngn.Authorize(testtype{}, "write", testtype{}))
	require.True(t, ngn.Authorize(testtype{}, "delete", testtype{}))

	ngn.Delete(testtype{}, "read,write", testtype{})
	require.False(t, ngn.Authorize(testtype{}, "read", testtype{}))
	require.False(t, ngn.Authorize(testtype{}, "write", testtype{}))
	require.True(t, ngn.Authorize(testtype{}, "delete", testtype{}))
}

func TestKey(t *testing.T) {
	testcases := []struct {
		val any
		exp string
	}{
		{testtype{}, "authngn.testtype"},
		{&testtype{}, "authngn.testtype"},
		{1, "int"},
		{"abcde", "string"},
		{false, "bool"},
	}

	for _, tc := range testcases {
		assert.Equal(t, tc.exp, key(tc.val))
	}
}

func TestRuleId(t *testing.T) {
	type val struct {
		ent    any
		action string
		res    any
	}
	testcases := []struct {
		val val
		exp string
	}{
		{val{&testtype{}, "read", 1}, "authngn.testtype-read-int"},
		{val{"abcde", "write", testtype{}}, "string-write-authngn.testtype"},
	}

	for _, tc := range testcases {
		assert.Equal(t, tc.exp, ruleId(tc.val.ent, tc.val.action, tc.val.res))
	}
}
