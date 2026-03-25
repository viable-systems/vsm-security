# vsm_security

Elixir security framework for the Viable Systems Model. Implements zone-based access control, bloom filter threat detection, and neural network threat prediction. Built on Phoenix with Guardian for JWT authentication.

## Status

- Version: 0.1.0
- Phoenix application requiring PostgreSQL
- Main module (`VsmSecurity`) is a stub (`hello/0` returns `:world`); actual functionality lives in submodules
- Depends on Nx ~> 0.10, Axon ~> 0.7, and EXLA for neural network features
- No Hex package configuration; not published

## What it does

The library provides 4 subsystems:

| Subsystem | Modules | Function |
|-----------|---------|----------|
| Z3N Zones | `Z3N.Zone`, `Z3N.Zones` | Dynamic security perimeters with adaptive trust scoring |
| Z3N Neural | `Z3N.Neural` | Threat prediction using Nx/Axon neural networks |
| Z3N Network | `Z3N.Network` | Encrypted peer-to-peer communication between zones |
| Bloom Filters | `BloomFilters.ThreatFilter` | Probabilistic threat signature matching via bloomex |

Additional modules:

| Module | Purpose |
|--------|---------|
| `Auth.Guardian` | JWT token generation and validation |
| `Auth.Pipeline` | Plug pipeline for authentication |
| `Auth.Plugs.VerifyZone` | Zone-based request authorization |
| `Patterns.ZeroTrust` | Zero-trust validation logic |
| `Patterns.DefenseInDepth` | Layered defense patterns |
| `Patterns.IncidentResponse` | Incident handling workflows |
| `Patterns.ThreatIntelligence` | Threat intelligence aggregation |
| `VsmIntegration` | Integration point with the broader VSM ecosystem |
| `SecurityAlert` | Alert struct and handling |

## Dependencies

Requires 20+ dependencies including Phoenix, Ecto/Postgrex, Guardian, Nx, EXLA, Axon, bloomex, JOSE, argon2, and cloak. See `mix.exs` for the full list.

## Setup

```bash
mix deps.get
mix ecto.setup   # requires running PostgreSQL
mix phx.server
```

## Usage

```elixir
# Create a security zone
{:ok, zone} = VsmSecurity.Z3N.Zone.start_link(id: "primary_zone")

# Validate access
request = %{
  user_id: "user123",
  action: "read",
  resource: "/api/data",
  signature: signature,
  public_key: public_key
}

case VsmSecurity.Z3N.Zone.validate_access("primary_zone", request) do
  {:allow, token} -> # proceed
  {:deny, reason} -> # reject
end

# Bloom filter threat checking
filter = VsmSecurity.BloomFilters.ThreatFilter.new(preset: :large)
filter = VsmSecurity.BloomFilters.ThreatFilter.add(filter, threat_signature)
VsmSecurity.BloomFilters.ThreatFilter.contains?(filter, request_signature)
```

## Limitations

- Main module is a stub; no unified API surface
- Requires PostgreSQL even for features that do not use persistence
- EXLA dependency makes compilation slow and platform-dependent
- Neural network models are not pre-trained; no training data or pipeline included
- No integration tests that exercise the full authentication + zone + threat detection flow end-to-end
- Z3N is a custom acronym (Zero-Trust, Zero-Knowledge, Zero-Latency) not an industry standard

## License

MIT
