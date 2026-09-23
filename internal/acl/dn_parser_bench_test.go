package acl

import "testing"

func BenchmarkAllowedDNParser(b *testing.B) {
	for _, scenario := range []struct {
		name      string
		subject   string
		targetDN  string
		attribute string
		required  Privilege
		want      bool
	}{
		{name: "anonymous_auth", attribute: "userPassword", required: Auth, want: true},
		{name: "self_read", subject: "uid=Alice,ou=People,dc=Example,dc=Com", attribute: "cn", required: Read, want: true},
		{name: "group_read", subject: "uid=Alice,ou=People,dc=Example,dc=Com", targetDN: "uid=Bob,ou=People,dc=Example,dc=Com", attribute: "cn", required: Read, want: true},
		{name: "nonmember_denied", subject: "uid=Bob,ou=People,dc=Example,dc=Com", attribute: "cn", required: Read},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			for _, mode := range []string{"uncached", "cached"} {
				b.Run(mode, func(b *testing.B) {
					registry, target, reader := newACLDNParserFixture(b)
					var rules []Rule
					for _, raw := range []string{
						`{0}to attrs=userPassword by self write by anonymous auth by * none`,
						`{1}to dn.subtree="ou=people,dc=example,dc=com" by self write by group="cn=alice-readers,ou=groups,dc=example,dc=com" read by * none`,
					} {
						rule, err := ParseRule(raw)
						if err != nil {
							b.Fatal(err)
						}
						rules = append(rules, rule)
					}
					policy, err := NewPolicy(nil, map[string][]Rule{"dc=example,dc=com": rules})
					if err != nil {
						b.Fatal(err)
					}
					groupDN, err := registry.NormalizeDN("cn=alice-readers,ou=groups,dc=example,dc=com")
					if err != nil {
						b.Fatal(err)
					}
					group := reader[groupDN.Key()]
					group.ReplaceValues("member", bytes(target.Entry.DN))
					reader[groupDN.Key()] = group
					if scenario.targetDN != "" {
						target.Entry.DN = scenario.targetDN
					}
					target.Attribute = scenario.attribute
					target.Value = nil
					target.DNNormalizer = registry
					if mode == "cached" {
						target.DNNormalizer = cachedACLDNNormalizer{registry}
					}
					subject := Subject{DN: scenario.subject}
					// Warm the bounded DN working set before measuring repeated checks.
					if got := policy.Allowed(subject, target, scenario.required, reader); got != scenario.want {
						b.Fatalf("Allowed = %v, want %v", got, scenario.want)
					}
					b.ReportAllocs()
					for b.Loop() {
						if got := policy.Allowed(subject, target, scenario.required, reader); got != scenario.want {
							b.Fatalf("Allowed = %v, want %v", got, scenario.want)
						}
					}
				})
			}
		})
	}
}

func BenchmarkAllowedDNParserParallel(b *testing.B) {
	for _, mode := range []string{"uncached", "cached"} {
		b.Run(mode, func(b *testing.B) {
			registry, target, reader := newACLDNParserFixture(b)
			rule, err := ParseRule("to attrs=userPassword by anonymous auth by * none")
			if err != nil {
				b.Fatal(err)
			}
			policy, err := NewPolicy(nil, map[string][]Rule{"dc=example,dc=com": {rule}})
			if err != nil {
				b.Fatal(err)
			}
			target.Attribute = "userPassword"
			target.Value = nil
			target.DNNormalizer = registry
			if mode == "cached" {
				target.DNNormalizer = cachedACLDNNormalizer{registry}
			}
			if !policy.Allowed(Subject{}, target, Auth, reader) {
				b.Fatal("warm authorization denied")
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(worker *testing.PB) {
				for worker.Next() {
					if !policy.Allowed(Subject{}, target, Auth, reader) {
						b.Error("authorization denied")
						return
					}
				}
			})
		})
	}
}
