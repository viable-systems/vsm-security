defmodule VsmSecurity.Z3N do
  @moduledoc """
  Z3N (Zones, Neural networks, Network security) - Core security architecture for VSM.
  
  Provides multi-layered defense through:
  - Zone-based isolation boundaries
  - ML-based threat detection
  - Distributed security mesh
  """
  
  alias VsmSecurity.Z3N.{Zones, Neural, Network}
  alias VsmSecurity.Z3N.{Supervisor, Metrics}
  
  @type z3n_state :: %{
    zones: Zones.t(),
    neural: Neural.t(),
    network: Network.t(),
    metrics: Metrics.t()
  }
  
  @doc """
  Initialize the Z3N security system
  """
  @spec initialize() :: {:ok, z3n_state()} | {:error, term()}
  def initialize do
    with {:ok, zones} <- Zones.setup(),
         {:ok, neural} <- Neural.initialize(),
         {:ok, network} <- Network.configure(),
         {:ok, metrics} <- Metrics.start() do
      state = %{
        zones: zones,
        neural: neural,
        network: network,
        metrics: metrics
      }
      
      # Start supervision tree
      Supervisor.start_link(state)
      
      {:ok, state}
    end
  end
  
  @doc """
  Process incoming request through Z3N security layers
  """
  @spec process_request(map(), map()) :: {:ok, map()} | {:error, term()}
  def process_request(request, context) do
    start_time = System.monotonic_time()
    
    with {:ok, zone} <- Zones.identify(request.source),
         :ok <- Zones.validate_transition(zone, request.destination),
         {:ok, analysis} <- Neural.analyze(request, context),
         :ok <- validate_analysis(analysis),
         {:ok, route} <- Network.route(request, zone, analysis) do
      
      # Record metrics
      Metrics.record_request(start_time, :success)
      
      execute_request(request, route, analysis)
    else
      {:error, :zone_violation} = error ->
        Metrics.record_request(start_time, :zone_violation)
        handle_zone_violation(request, error)
        
      {:error, :anomaly_detected} = error ->
        Metrics.record_request(start_time, :anomaly)
        quarantine_request(request, error)
        
      {:error, reason} = error ->
        Metrics.record_request(start_time, :error)
        handle_error(reason, request)
        error
    end
  end
  
  @doc """
  Get current Z3N system status
  """
  @spec status() :: map()
  def status do
    %{
      zones: Zones.status(),
      neural: Neural.status(),
      network: Network.status(),
      metrics: Metrics.current(),
      health: calculate_health()
    }
  end
  
  @doc """
  Emergency shutdown of Z3N system
  """
  @spec emergency_shutdown(String.t()) :: :ok
  def emergency_shutdown(reason) do
    Logger.error("Z3N Emergency Shutdown: #{reason}")
    
    # Gracefully shutdown components
    Network.shutdown()
    Neural.shutdown()
    Zones.lockdown()
    
    # Notify administrators
    notify_emergency(reason)
    
    :ok
  end
  
  # Private functions
  
  defp validate_analysis(%{threat_level: level, confidence: conf}) do
    cond do
      level == :critical and conf > 0.9 -> {:error, :anomaly_detected}
      level == :high and conf > 0.8 -> {:error, :anomaly_detected}
      true -> :ok
    end
  end
  
  defp execute_request(request, route, analysis) do
    enriched_request = Map.merge(request, %{
      z3n_route: route,
      z3n_analysis: analysis,
      z3n_timestamp: DateTime.utc_now()
    })
    
    {:ok, enriched_request}
  end
  
  defp handle_zone_violation(request, error) do
    Logger.warn("Zone violation detected: #{inspect(request.source)} -> #{inspect(request.destination)}")
    
    # Log to audit trail
    AuditLog.record(:zone_violation, request)
    
    # Block request
    {:error, error}
  end
  
  defp quarantine_request(request, error) do
    Logger.error("Anomaly detected, quarantining request: #{inspect(request)}")
    
    # Move to quarantine for analysis
    Quarantine.add(request)
    
    # Alert security team
    SecurityAlert.send(:anomaly, request)
    
    {:error, error}
  end
  
  defp handle_error(reason, request) do
    Logger.error("Z3N error: #{inspect(reason)}, request: #{inspect(request)}")
    {:error, reason}
  end
  
  defp calculate_health do
    zone_health = Zones.health_score()
    neural_health = Neural.health_score()
    network_health = Network.health_score()
    
    # Weighted average
    (zone_health * 0.3 + neural_health * 0.4 + network_health * 0.3)
    |> round()
  end
  
  defp notify_emergency(reason) do
    # Send notifications through multiple channels
    Task.async_stream(
      ["email", "sms", "slack", "pagerduty"],
      fn channel ->
        AlertChannel.send(channel, "Z3N Emergency: #{reason}")
      end
    )
    |> Stream.run()
  end
end