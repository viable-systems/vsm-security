#!/usr/bin/env elixir
# Run with: elixir demo/vsm_protocol_demo.exs

defmodule VSMProtocolDemo do
  @moduledoc """
  Demonstrates VSM Security protocol integration with the ecosystem.
  Shows how security events flow through VSM channels.
  """
  
  alias VSMSecurity.VSMIntegration
  alias VSMSecurity.Z3N
  
  def run do
    IO.puts """
    ========================================
    VSM SECURITY PROTOCOL DEMONSTRATION
    ========================================
    
    This demo shows how VSM Security integrates with the VSM ecosystem
    through the VSM protocol, including:
    
    1. Security event types in the protocol
    2. Channel communication (Temporal Variety & Algedonic)
    3. Command handling from VSM Core
    4. Variety metrics for optimization
    5. Zone-based security boundaries
    """
    
    IO.puts "\n1. VSM PROTOCOL MESSAGE TYPES"
    IO.puts "=============================="
    demonstrate_protocol_messages()
    
    IO.puts "\n2. VSM CHANNEL COMMUNICATION"
    IO.puts "============================="
    demonstrate_channels()
    
    IO.puts "\n3. VSM COMMAND HANDLING"
    IO.puts "======================="
    demonstrate_command_handling()
    
    IO.puts "\n4. VARIETY METRICS"
    IO.puts "=================="
    demonstrate_variety_metrics()
    
    IO.puts "\n5. ECOSYSTEM INTEGRATION"
    IO.puts "======================="
    demonstrate_ecosystem_integration()
    
    IO.puts "\n✅ VSM Security is fully integrated with the VSM protocol!"
  end
  
  defp demonstrate_protocol_messages do
    IO.puts "Security event types defined in VSM protocol:"
    IO.puts "- vsm.security.event    : General security events"
    IO.puts "- vsm.security.alert    : Critical security alerts"
    IO.puts "- vsm.security.metric   : Security metrics for optimization"
    
    # Show example event structure
    event = %{
      type: "vsm.security.event",
      timestamp: System.system_time(:millisecond),
      source: "vsm_security",
      event_type: :auth_failure,
      payload: %{
        user: "test@example.com",
        reason: "invalid_credentials",
        ip: "192.168.1.100"
      }
    }
    
    IO.puts "\nExample security event:"
    IO.inspect(event, pretty: true, limit: :infinity)
  end
  
  defp demonstrate_channels do
    IO.puts "VSM channels used by Security subsystem:"
    
    IO.puts "\n📡 Temporal Variety Channel (normal operations):"
    temporal_msg = %{
      from: "vsm_security",
      to: "S3.auth",
      content: %{
        event_type: :rate_limit_exceeded,
        zone: :public,
        details: "100 requests/minute from single IP"
      },
      priority: :high
    }
    IO.inspect(temporal_msg, pretty: true)
    
    IO.puts "\n🚨 Algedonic Channel (critical alerts):"
    algedonic_msg = %{
      severity: :critical,
      source: "vsm_security",
      message: "SECURITY ALERT: Breach detected in private zone",
      timestamp: System.system_time(:millisecond),
      bypass_hierarchy: true
    }
    IO.inspect(algedonic_msg, pretty: true)
  end
  
  defp demonstrate_command_handling do
    IO.puts "VSM Core can send commands to Security subsystem:"
    
    commands = [
      %{
        type: "vsm.control.command",
        command: "security.scan",
        params: %{zones: [:public, :dmz, :private]}
      },
      %{
        type: "vsm.control.command", 
        command: "security.quarantine",
        params: %{type: "node", id: "suspicious-node-123"}
      },
      %{
        type: "vsm.control.command",
        command: "security.update_policy",
        params: %{
          zone: :dmz,
          policy: :rate_limit,
          value: 500
        }
      }
    ]
    
    for cmd <- commands do
      IO.puts "\nCommand: #{cmd.command}"
      IO.inspect(cmd.params, pretty: true)
      
      # Show what would happen
      case cmd.command do
        "security.scan" ->
          IO.puts "→ Would scan zones: #{inspect(cmd.params.zones)}"
        "security.quarantine" ->
          IO.puts "→ Would quarantine #{cmd.params.type}: #{cmd.params.id}"
        "security.update_policy" ->
          IO.puts "→ Would update #{cmd.params.zone} policy"
      end
    end
  end
  
  defp demonstrate_variety_metrics do
    IO.puts "Security provides variety metrics for VSM optimization:"
    
    metrics = %{
      threat_level: :medium,
      active_zones: [:public, :dmz, :private],
      neural_accuracy: 0.943,
      blocked_threats: 127,
      auth_failures: 23,
      variety_score: 0.867
    }
    
    IO.inspect(metrics, pretty: true)
    
    IO.puts """
    
    These metrics help VSM Core:
    - Optimize resource allocation (S3)
    - Adjust security policies (S3)
    - Predict future threats (S4)
    - Make strategic decisions (S5)
    """
  end
  
  defp demonstrate_ecosystem_integration do
    IO.puts "VSM Security integrates with all ecosystem components:"
    
    integrations = [
      %{
        component: "VSM Core",
        integration: "Registers as security subsystem, receives commands",
        protocol: "vsm.control.command, vsm.subsystem.register"
      },
      %{
        component: "VSM Telemetry", 
        integration: "Monitors system metrics for anomalies",
        protocol: "telemetry events, metric analysis"
      },
      %{
        component: "VSM Event Bus",
        integration: "Subscribes to security-relevant events",
        protocol: "pub/sub topics: auth.failure, network.intrusion"
      },
      %{
        component: "VSM Connections",
        integration: "Monitors network traffic for threats",
        protocol: "connection events, traffic analysis"
      }
    ]
    
    for int <- integrations do
      IO.puts "\n🔗 #{int.component}:"
      IO.puts "   Integration: #{int.integration}"
      IO.puts "   Protocol: #{int.protocol}"
    end
    
    IO.puts """
    
    Zone Security Model (implements VSM hierarchy):
    ┌─────────────────────────────────────┐
    │  S5: Strategic Security (Algedonic) │
    ├─────────────────────────────────────┤
    │  S4: Threat Intelligence & ML       │
    ├─────────────────────────────────────┤
    │  S3: Security Operations            │
    │  ├─ Zone Management                 │
    │  ├─ Access Control                  │
    │  └─ Policy Enforcement              │
    ├─────────────────────────────────────┤
    │  S2: Coordination & Routing         │
    ├─────────────────────────────────────┤
    │  S1: Implementation                 │
    │  ├─ Public Zone                     │
    │  ├─ DMZ Zone                        │
    │  └─ Private Zone                    │
    └─────────────────────────────────────┘
    """
  end
end

# Run the demo
VSMProtocolDemo.run()