# Ratelimiter in Fatline authority bindings

Ratelimiter owns machine-enforceable rate/lifecycle policy representation and profile capability validation. It does not own organization business rules, tenant registration, authorization grants, billing, deployment identity, or the durable Fatline binding registry.

The Fatline control plane stores ratelimiter as one machine-policy component of a compiled binding:

```text
Org business/security authority
        |
        +-- auth policy digest + auth execution profile
        |
        `-- ratelimiter PolicyCode + ratelimiter execution profile
                         |
                         v
                  compiled binding
```

`PolicyBinding` is the cross-language representation of the ratelimiter half of that contract. `profile` is the stable execution-shape identifier returned by `ProfileID`; `policy_code` is decimal text rather than a JSON number so JavaScript and other IEEE-754 consumers cannot lose `uint64` precision.

Human aliases such as `smoke-10m` remain navigation/configuration inputs. Durable Fatline bindings freeze the canonical `PolicyCode`, not the alias.

The ownership rule remains:

```text
ratelimiter: policy mechanics and executable profile capabilities
Logma/Fatline control plane: durable compiled binding and tenant/service placement
Huram: exact-source composition and qualification evidence
```

A binding validator must call the same ratelimiter policy/profile/entitlement validation used outside Fatline. A business rule may narrow an entitlement, but a tenant/service/route binding cannot use ratelimiter to expand its parent organization's ceiling.
