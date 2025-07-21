# VSM Security

Zero-Trust, Zero-Knowledge, Zero-Latency (Z3N) Security System for Viable Systems Model.

## Overview

VSM Security implements a comprehensive security framework based on the Z3N principles:

- **Zero-Trust**: No implicit trust, all interactions are verified
- **Zero-Knowledge**: Cryptographic proofs without revealing sensitive data
- **Zero-Latency**: Real-time threat detection and response using neural networks and bloom filters

## Key Components

### Z3N Zones
- Dynamic security perimeters with adaptive trust scoring
- Neural-based threat detection
- Zero-knowledge proof verification

### Neural Security
- Real-time threat prediction using Nx/Axon
- Pattern recognition for anomaly detection
- Adaptive learning from security events

### Bloom Filters
- Probabilistic threat signature matching
- Memory-efficient threat database
- Support for counting filters with removable items

### Network Management
- Encrypted peer-to-peer communication
- Dynamic routing and topology management
- Health monitoring and self-healing

## Setup

1. Install dependencies:
```bash
mix deps.get
```

2. Create and migrate database:
```bash
mix ecto.setup
```

3. Start the application:
```bash
mix phx.server
```

## Configuration

See `config/config.exs` for configuration options including:
- Z3N zone parameters
- Neural network settings
- Bloom filter presets
- Network topology options

## Usage

### Creating a Z3N Zone

```elixir
{:ok, zone} = VsmSecurity.Z3N.Zone.start_link(id: "primary_zone")
```

### Validating Access

```elixir
request = %{
  user_id: "user123",
  action: "read",
  resource: "/api/data",
  signature: signature,
  public_key: public_key
}

case VsmSecurity.Z3N.Zone.validate_access("primary_zone", request) do
  {:allow, token} -> # Access granted
  {:deny, reason} -> # Access denied
end
```

### Threat Detection

```elixir
# Add threat signature
filter = VsmSecurity.BloomFilters.ThreatFilter.new(preset: :large)
filter = VsmSecurity.BloomFilters.ThreatFilter.add(filter, threat_signature)

# Check for threats
is_threat = VsmSecurity.BloomFilters.ThreatFilter.contains?(filter, request_signature)
```

## Architecture

The system follows OTP principles with:
- Supervised GenServer processes for zones
- Dynamic supervisor for scaling
- Registry for zone discovery
- PubSub for event distribution

## Testing

Run tests with:
```bash
mix test
```

## License

Part of the Viable Systems Model project.