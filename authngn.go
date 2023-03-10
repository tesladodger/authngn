package authngn

import (
	"reflect"
	"strings"
)

// AuthFunc is a function that takes an entity and a resource, and returns
// true if the action should be authorized.
type AuthFunc func(ent, res any) bool

// Authngn contains the methods to register and evaluate authorization rules.
type Authngn struct {
	rules map[string]AuthFunc
}

// New initializes a new authorization engine.
func New() *Authngn {
	return &Authngn{make(map[string]AuthFunc)}
}

// Register adds a new rule to the engine.
// A previously registered rule matching the same criteria will be replaced.
//
// Only the underlying types of ent and res are used: registering User{} is
// equivalent to registering &User{}.
//
// The action can be a set of actions, separated by a comma:
// `read,write,delete`
func (n *Authngn) Register(ent any, action string, res any, f AuthFunc) {
	actions := strings.Split(action, ",")
	for _, act := range actions {
		n.rules[ruleId(ent, act, res)] = f
	}
}

// Authorize evaluates the rule for the given parameters.
// It returns false if there is no such rule.
//
// The action can be a set of actions, separated by a comma:
// `read,write,delete`. It returns true iff all actions pass authorization.
func (n *Authngn) Authorize(ent any, action string, res any) bool {
	actions := strings.Split(action, ",")
	for _, act := range actions {
		if !n.authorize(ent, act, res) {
			return false
		}
	}
	return true
}

func (n *Authngn) authorize(ent any, action string, res any) bool {
	auth, ok := n.rules[ruleId(ent, action, res)]
	if !ok {
		return false
	}

	return auth(ent, res)
}

// Delete removes the rule from the engine.
//
// The action can be a set of actions, separated by a comma:
// `read,write,delete`
func (n *Authngn) Delete(ent any, action string, res any) {
	actions := strings.Split(action, ",")
	for _, act := range actions {
		n.delete(ent, act, res)
	}
}

func (n *Authngn) delete(ent any, action string, res any) {
	delete(n.rules, ruleId(ent, action, res))
}

// Contains returns true if a rule that matches the given criteria has been
// registered.
func (n *Authngn) Contains(ent any, action string, res any) bool {
	_, ok := n.rules[ruleId(ent, action, res)]
	return ok
}

// ruleId returns an identifier for the action and types of ent and res.
func ruleId(ent any, action string, res any) string {
	return strings.Join([]string{
		key(ent),
		action,
		key(res),
	}, "-")
}

// key returns an identifier for the underlying type of val, ignoring pointers.
func key(val any) string {
	return strings.Replace(reflect.TypeOf(val).String(), "*", "", -1)
}
