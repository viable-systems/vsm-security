defmodule VSMSecurity.VSMIntegration do
  @moduledoc """
  Integration module for VSM Security with other VSM ecosystem components.
  Implements the VSM protocol for security events and channels.
  """
  
  alias VSMSecurity.Z3N
  alias VSMSecurity.Telemetry

  # VSM Protocol message types for security
  @security_event_type "vsm.security.event"
  @security_alert_type "vsm.security.alert"
  @security_metric_type "vsm.security.metric"

  @doc """
  Initialize VSM protocol integration
  """
  def init do
    # Register with VSM Core if available
    if Code.ensure_loaded?(VSMCore) do
      register_with_vsm_core()
    end

    # Setup telemetry integration
    if Code.ensure_loaded?(VSMTelemetry) do
      setup_telemetry_integration()
    end

    # Configure event bus if available
    if Code.ensure_loaded?(VSMEventBus) do
      setup_event_bus_integration()
    end

    :ok
  end

  @doc """
  Send security event through VSM channels
  """
  def send_security_event(event_type, payload) do
    event = %{
      type: @security_event_type,
      timestamp: System.system_time(:millisecond),
      source: "vsm_security",
      event_type: event_type,
      payload: payload
    }

    # Send through algedonic channel for critical events
    if critical_event?(event_type) do
      send_algedonic_signal(event)
    end

    # Send through temporal variety channel for normal events
    send_temporal_variety(event)

    # Publish to event bus if available
    if Code.ensure_loaded?(VSMEventBus) do
      VSMEventBus.publish("security.#{event_type}", event)
    end

    :ok
  end

  @doc """
  Handle incoming VSM protocol messages
  """
  def handle_vsm_message(%{type: "vsm.control.command", command: command, params: params}) do
    case command do
      "security.scan" ->
        perform_security_scan(params)
      
      "security.quarantine" ->
        quarantine_entity(params)
      
      "security.update_policy" ->
        update_security_policy(params)
      
      _ ->
        {:error, :unknown_command}
    end
  end

  def handle_vsm_message(%{type: "vsm.variety.request", channel: channel}) do
    # Provide security variety metrics
    metrics = gather_security_metrics(channel)
    {:ok, metrics}
  end

  def handle_vsm_message(_), do: {:error, :invalid_message}

  # Private functions

  defp register_with_vsm_core do
    VSMCore.register_subsystem(%{
      id: "vsm_security",
      type: :security,
      capabilities: [:z3n, :neural_detection, :zone_control, :threat_analysis],
      channels: [:temporal_variety, :algedonic],
      version: "0.1.0"
    })
  end

  defp setup_telemetry_integration do
    # Attach to VSM telemetry events
    :telemetry.attach_many(
      "vsm-security-telemetry",
      [
        [:vsm_core, :message, :received],
        [:vsm_core, :algedonic, :signal],
        [:vsm_telemetry, :metric, :recorded]
      ],
      &handle_telemetry_event/4,
      nil
    )
  end

  defp setup_event_bus_integration do
    # Subscribe to relevant security topics
    VSMEventBus.subscribe("system.anomaly")
    VSMEventBus.subscribe("network.intrusion")
    VSMEventBus.subscribe("auth.failure")
    VSMEventBus.subscribe("rate_limit.exceeded")
  end

  defp critical_event?(event_type) do
    event_type in [:breach_detected, :ddos_attack, :zombie_detected, :critical_vulnerability]
  end

  defp send_algedonic_signal(event) do
    if Code.ensure_loaded?(VSMCore.Channels.Algedonic) do
      VSMCore.Channels.Algedonic.send_alert(%{
        severity: :critical,
        source: "vsm_security",
        message: format_security_alert(event),
        timestamp: event.timestamp,
        bypass_hierarchy: true
      })
    end
  end

  defp send_temporal_variety(event) do
    if Code.ensure_loaded?(VSMCore.Channels.TemporalVariety) do
      VSMCore.Channels.TemporalVariety.send_message(%{
        from: "vsm_security",
        to: determine_recipient(event),
        content: event,
        priority: event_priority(event.event_type)
      })
    end
  end

  defp perform_security_scan(params) do
    zones = params[:zones] || [:public, :dmz, :private]
    
    results = Enum.map(zones, fn zone ->
      {zone, Z3N.Zones.scan_zone(zone)}
    end)

    {:ok, results}
  end

  defp quarantine_entity(%{type: type, id: id} = params) do
    case type do
      "node" -> Z3N.Network.quarantine_node(id)
      "user" -> Z3N.Zone.quarantine_user(id)
      "service" -> Z3N.Zone.quarantine_service(id)
      _ -> {:error, :invalid_entity_type}
    end
  end

  defp update_security_policy(params) do
    # Update security policies across zones
    Z3N.update_policies(params)
  end

  defp gather_security_metrics(channel) do
    %{
      threat_level: Z3N.get_threat_level(),
      active_zones: Z3N.Zones.list_active_zones(),
      neural_accuracy: Z3N.Neural.get_accuracy_metrics(),
      blocked_threats: get_blocked_threat_count(),
      auth_failures: get_auth_failure_count(),
      variety_score: calculate_security_variety()
    }
  end

  defp format_security_alert(event) do
    "SECURITY ALERT: #{event.event_type} detected at #{event.timestamp}"
  end

  defp determine_recipient(event) do
    case event.event_type do
      :auth_failure -> "S3.auth"
      :network_anomaly -> "S3.network"
      :policy_violation -> "S3.control"
      _ -> "S3"
    end
  end

  defp event_priority(event_type) do
    case event_type do
      type when type in [:breach_detected, :ddos_attack] -> :critical
      type when type in [:zombie_detected, :auth_failure] -> :high
      type when type in [:rate_limit_exceeded, :anomaly_detected] -> :medium
      _ -> :normal
    end
  end

  defp get_blocked_threat_count do
    # Get from ETS or telemetry
    0
  end

  defp get_auth_failure_count do
    # Get from ETS or telemetry  
    0
  end

  defp calculate_security_variety do
    # Calculate Shannon entropy of security events
    1.0
  end

  defp handle_telemetry_event(_event_name, measurements, metadata, _config) do
    # Process telemetry events from other VSM components
    if security_relevant?(metadata) do
      analyze_for_threats(measurements, metadata)
    end
  end

  defp security_relevant?(metadata) do
    metadata[:source] in ["vsm_core", "vsm_connections", "vsm_event_bus"] ||
    metadata[:type] in [:auth, :network, :rate_limit]
  end

  defp analyze_for_threats(measurements, metadata) do
    # Use neural network to analyze patterns
    Z3N.Neural.analyze_event(%{
      measurements: measurements,
      metadata: metadata,
      timestamp: System.system_time(:millisecond)
    })
  end
end