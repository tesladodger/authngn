# Authngn

Stupidly simple authorization engine.

```
go get -u github.com/tesladodger/authngn
```

## Usage

Register the rules:

```
ngn := authngn.New()
ngn.Register(User{}, "read,write,delete", Resource{}, func(ent, res any) bool {
    user := ent.(User)
    res := res.(Resource)
    return user.id == resource.owner
})
```

Assert authorization:
```
ok := ngn.Authorize(user, "read", resource)
```
