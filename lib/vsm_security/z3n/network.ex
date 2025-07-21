defmodule VsmSecurity.Z3N.Network do
  @moduledoc """
  Network security layer implementing distributed security mesh.
  
  Features:
  - Zone-aware routing algorithms
  - Zombie detection mechanisms
  - Traffic analysis and filtering
  - Service mesh security
  """
  
  use GenServer
  require Logger
  
  alias VsmSecurity.Z3N.Network.{Router, ZombieDetector, TrafficAnalyzer}
  
  @type route :: %{
    path: [atom()],
    proxy: atom() | nil,
    encryption: atom(),
    policies: [atom()]
  }
  
  @routing_table %{
    public: [:api_gateway, :cdn, :web_ui],
    dmz: [:auth_proxy, :load_balancer, :rate_limiter, :waf],
    private: [:vsm_core, :database, :neural_engine, :event_bus]
  }
  
  @zombie_thresholds %{
    cpu_usage: 90,
    memory_usage: 85,
    network_anomaly_score: 0.8,
    repetitive_pattern_count: 100,
    lateral_movement_attempts: 5
  }
  
  # Client API
  
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Configure network security mesh
  """
  @spec configure() :: {:ok, map()} | {:error, term()}
  def configure do
    GenServer.call(__MODULE__, :configure)
  end
  
  @doc """
  Route request through security mesh
  """
  @spec route(map(), atom(), map()) :: {:ok, route()} | {:error, term()}
  def route(request, source_zone, analysis) do
    GenServer.call(__MODULE__, {:route, request, source_zone, analysis})
  end
  
  @doc """
  Analyze network traffic
  """
  @spec analyze_traffic(map()) :: {:ok, map()} | {:error, term()}
  def analyze_traffic(traffic_data) do
    GenServer.call(__MODULE__, {:analyze_traffic, traffic_data})
  end
  
  @doc """
  Check for zombie nodes
  """
  @spec check_zombie(String.t()) :: {:ok, map()} | {:error, term()}
  def check_zombie(node_id) do
    GenServer.call(__MODULE__, {:check_zombie, node_id})
  end
  
  @doc """
  Quarantine suspected zombie
  """
  @spec quarantine_node(String.t(), map()) :: :ok
  def quarantine_node(node_id, reason) do
    GenServer.cast(__MODULE__, {:quarantine, node_id, reason})
  end
  
  @doc """
  Get network status
  """
  @spec status() :: map()
  def status do
    GenServer.call(__MODULE__, :status)
  end
  
  @doc """
  Get health score
  """
  @spec health_score() :: float()
  def health_score do
    GenServer.call(__MODULE__, :health_score)
  end
  
  @doc """
  Shutdown network security
  """
  @spec shutdown() :: :ok
  def shutdown do
    GenServer.stop(__MODULE__, :normal)
  end
  
  # Server callbacks
  
  @impl true
  def init(_opts) do
    # Initialize network security components
    :ets.new(:network_routes, [:set, :protected, :named_table])
    :ets.new(:traffic_stats, [:set, :public, :named_table])
    :ets.new(:zombie_watch, [:set, :protected, :named_table])
    
    state = %{
      router: nil,
      zombie_detector: nil,
      traffic_analyzer: nil,
      mesh_config: init_mesh_config(),
      quarantined_nodes: MapSet.new(),
      metrics: init_metrics()
    }
    
    # Schedule initialization
    Process.send_after(self(), :delayed_init, 100)
    
    {:ok, state}
  end
  
  @impl true
  def handle_call(:configure, _from, state) do
    with {:ok, router} <- Router.start_link(@routing_table),
         {:ok, zombie_detector} <- ZombieDetector.start_link(@zombie_thresholds),
         {:ok, traffic_analyzer} <- TrafficAnalyzer.start_link() do
      
      new_state = %{state |
        router: router,
        zombie_detector: zombie_detector,
        traffic_analyzer: traffic_analyzer
      }
      
      # Start monitoring
      schedule_health_check()
      schedule_zombie_scan()
      
      result = %{
        mesh_topology: :zone_aware,
        encryption: :mtls,
        routing_table: @routing_table,
        status: :active
      }
      
      {:reply, {:ok, result}, new_state}
    else
      error ->
        {:reply, error, state}
    end
  end
  
  @impl true
  def handle_call({:route, request, source_zone, analysis}, _from, state) do
    destination_service = extract_destination(request)
    
    # Check if node is quarantined
    if quarantined?(request.source_node, state) do
      {:reply, {:error, :node_quarantined}, state}
    else
      # Determine route based on zones and analysis
      route_result = determine_route(
        source_zone,
        destination_service,
        analysis,
        state
      )
      
      case route_result do
        {:ok, route} ->
          # Record routing decision
          record_route(request, route, state)
          {:reply, {:ok, route}, state}
          
        error ->
          {:reply, error, state}
      end
    end
  end
  
  @impl true
  def handle_call({:analyze_traffic, traffic_data}, _from, state) do
    if state.traffic_analyzer do
      analysis = TrafficAnalyzer.analyze(state.traffic_analyzer, traffic_data)
      
      # Update traffic statistics
      update_traffic_stats(analysis)
      
      # Check for anomalies
      anomalies = detect_traffic_anomalies(analysis, state)
      
      result = Map.merge(analysis, %{anomalies: anomalies})
      {:reply, {:ok, result}, state}
    else
      {:reply, {:error, :analyzer_not_initialized}, state}
    end
  end
  
  @impl true
  def handle_call({:check_zombie, node_id}, _from, state) do
    if state.zombie_detector do
      # Collect node metrics
      metrics = collect_node_metrics(node_id)
      
      # Run zombie detection
      detection_result = ZombieDetector.analyze(
        state.zombie_detector,
        node_id,
        metrics
      )
      
      # Update zombie watch list
      update_zombie_watch(node_id, detection_result)
      
      {:reply, {:ok, detection_result}, state}
    else
      {:reply, {:error, :detector_not_initialized}, state}
    end
  end
  
  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      router: get_component_status(state.router),
      zombie_detector: get_component_status(state.zombie_detector),
      traffic_analyzer: get_component_status(state.traffic_analyzer),
      mesh_config: state.mesh_config,
      quarantined_nodes: MapSet.size(state.quarantined_nodes),
      metrics: get_current_metrics(state)
    }
    
    {:reply, status, state}
  end
  
  @impl true
  def handle_call(:health_score, _from, state) do
    score = calculate_network_health(state)
    {:reply, score, state}
  end
  
  @impl true
  def handle_cast({:quarantine, node_id, reason}, state) do
    Logger.warn("Quarantining node #{node_id}: #{inspect(reason)}")
    
    # Add to quarantine set
    new_state = %{state |
      quarantined_nodes: MapSet.put(state.quarantined_nodes, node_id)
    }
    
    # Isolate node
    isolate_node(node_id, reason)
    
    # Update routing table
    update_routing_for_quarantine(node_id)
    
    # Notify administrators
    notify_quarantine(node_id, reason)
    
    {:noreply, new_state}
  end
  
  @impl true
  def handle_info(:delayed_init, state) do
    # Initialize components directly without self-call
    with {:ok, router} <- Router.start_link(@routing_table),
         {:ok, zombie_detector} <- ZombieDetector.start_link(@zombie_thresholds),
         {:ok, traffic_analyzer} <- TrafficAnalyzer.start_link() do
      
      new_state = %{state |
        router: router,
        zombie_detector: zombie_detector,
        traffic_analyzer: traffic_analyzer
      }
      
      # Start monitoring
      schedule_health_check()
      schedule_zombie_scan()
      
      Logger.info("Network security initialized")
      {:noreply, new_state}
    else
      error ->
        Logger.error("Failed to initialize network security: #{inspect(error)}")
        {:noreply, state}
    end
  end
  
  @impl true
  def handle_info(:health_check, state) do
    # Check health of all components
    check_component_health(state)
    
    # Schedule next check
    schedule_health_check()
    
    {:noreply, state}
  end
  
  @impl true
  def handle_info(:zombie_scan, state) do
    # Scan all nodes for zombie behavior
    scan_for_zombies(state)
    
    # Schedule next scan
    schedule_zombie_scan()
    
    {:noreply, state}
  end
  
  # Private functions
  
  defp init_mesh_config do
    %{
      topology: :zone_aware,
      encryption: %{
        internal: :mtls,
        external: :tls13,
        algorithms: [:aes_256_gcm, :chacha20_poly1305]
      },
      policies: %{
        zero_trust: true,
        least_privilege: true,
        defense_in_depth: true
      },
      timeouts: %{
        connect: 5000,
        request: 30000,
        idle: 60000
      }
    }
  end
  
  defp extract_destination(request) do
    request[:destination] || 
    request[:target_service] || 
    parse_path_for_service(request[:path])
  end
  
  defp parse_path_for_service(nil), do: nil
  defp parse_path_for_service(path) do
    # Extract service name from path
    # Example: "/api/users" -> :api_gateway
    case String.split(path, "/", trim: true) do
      [service | _] -> String.to_atom(service)
      _ -> nil
    end
  end
  
  defp quarantined?(node_id, state) do
    MapSet.member?(state.quarantined_nodes, node_id)
  end
  
  defp determine_route(source_zone, destination, analysis, state) do
    # Find destination zone
    dest_zone = find_service_zone(destination)
    
    cond do
      # Blocked by analysis
      analysis.recommendation == :block ->
        {:error, :blocked_by_analysis}
        
      # No destination found
      dest_zone == nil ->
        {:error, :unknown_destination}
        
      # Check zone transition rules
      not allowed_transition?(source_zone, dest_zone) ->
        {:error, :zone_transition_denied}
        
      # Route through proxy if different zones
      source_zone != dest_zone ->
        build_proxied_route(source_zone, dest_zone, destination, analysis)
        
      # Direct route within same zone
      true ->
        build_direct_route(destination, analysis)
    end
  end
  
  defp find_service_zone(service) do
    Enum.find_value(@routing_table, fn {zone, services} ->
      if service in services, do: zone
    end)
  end
  
  defp allowed_transition?(from_zone, to_zone) do
    # Define allowed zone transitions
    transitions = %{
      public: [:dmz],
      dmz: [:public, :private],
      private: [:dmz]
    }
    
    allowed = Map.get(transitions, from_zone, [])
    to_zone in allowed or from_zone == to_zone
  end
  
  defp build_proxied_route(from_zone, to_zone, destination, analysis) do
    proxy = determine_proxy(from_zone, to_zone)
    
    route = %{
      path: [from_zone, proxy, to_zone, destination],
      proxy: proxy,
      encryption: :mtls,
      policies: apply_route_policies(analysis)
    }
    
    {:ok, route}
  end
  
  defp build_direct_route(destination, analysis) do
    route = %{
      path: [destination],
      proxy: nil,
      encryption: :internal_tls,
      policies: apply_route_policies(analysis)
    }
    
    {:ok, route}
  end
  
  defp determine_proxy(:public, :private), do: :auth_proxy
  defp determine_proxy(:private, :public), do: :reverse_proxy
  defp determine_proxy(_, _), do: :load_balancer
  
  defp apply_route_policies(analysis) do
    policies = []
    
    policies = if analysis.threat_level in [:high, :critical] do
      [:deep_packet_inspection | policies]
    else
      policies
    end
    
    policies = if analysis.recommendation == :rate_limit do
      [:rate_limiting | policies]
    else
      policies
    end
    
    policies = if analysis.recommendation == :monitor do
      [:enhanced_logging | policies]
    else
      policies
    end
    
    policies
  end
  
  defp record_route(request, route, state) do
    key = {:route, request.id, System.system_time()}
    value = %{
      request: request,
      route: route,
      timestamp: DateTime.utc_now()
    }
    
    :ets.insert(:network_routes, {key, value})
    
    # Update metrics
    update_in(state.metrics.routes_processed, &(&1 + 1))
  end
  
  defp update_traffic_stats(analysis) do
    stats = %{
      timestamp: System.system_time(),
      packet_count: analysis[:packet_count] || 0,
      byte_count: analysis[:byte_count] || 0,
      protocol_distribution: analysis[:protocols] || %{},
      top_sources: analysis[:top_sources] || [],
      top_destinations: analysis[:top_destinations] || []
    }
    
    :ets.insert(:traffic_stats, {{:stats, :latest}, stats})
  end
  
  defp detect_traffic_anomalies(analysis, _state) do
    anomalies = []
    
    # Check for DDoS patterns
    if analysis[:requests_per_second] > 10000 do
      anomalies = [{:possible_ddos, analysis[:requests_per_second]} | anomalies]
    end
    
    # Check for scanning activity
    if analysis[:unique_destinations] > 100 do
      anomalies = [{:port_scanning, analysis[:unique_destinations]} | anomalies]
    end
    
    # Check for data exfiltration
    if analysis[:outbound_bytes] > 1_000_000_000 do  # 1GB
      anomalies = [{:data_exfiltration, analysis[:outbound_bytes]} | anomalies]
    end
    
    anomalies
  end
  
  defp collect_node_metrics(node_id) do
    # In production, collect real metrics from monitoring system
    %{
      node_id: node_id,
      cpu_usage: :rand.uniform(100),
      memory_usage: :rand.uniform(100),
      network_io: %{
        bytes_in: :rand.uniform(1_000_000),
        bytes_out: :rand.uniform(1_000_000),
        packets_in: :rand.uniform(10000),
        packets_out: :rand.uniform(10000)
      },
      process_count: :rand.uniform(200),
      connection_count: :rand.uniform(1000),
      error_rate: :rand.uniform() * 0.1,
      patterns: detect_behavioral_patterns(node_id)
    }
  end
  
  defp detect_behavioral_patterns(node_id) do
    # Simplified pattern detection
    patterns = []
    
    # Check for repetitive behavior
    if :rand.uniform() > 0.8 do
      patterns = [:repetitive_requests | patterns]
    end
    
    # Check for unusual timing
    if :rand.uniform() > 0.9 do
      patterns = [:unusual_timing | patterns]
    end
    
    # Check for lateral movement
    if :rand.uniform() > 0.95 do
      patterns = [:lateral_movement | patterns]
    end
    
    patterns
  end
  
  defp update_zombie_watch(node_id, detection_result) do
    key = {:zombie_watch, node_id}
    value = Map.merge(detection_result, %{
      last_check: DateTime.utc_now(),
      check_count: get_check_count(node_id) + 1
    })
    
    :ets.insert(:zombie_watch, {key, value})
    
    # Auto-quarantine if high confidence zombie
    if detection_result.zombie_probability > 0.9 do
      quarantine_node(node_id, detection_result)
    end
  end
  
  defp get_check_count(node_id) do
    case :ets.lookup(:zombie_watch, {:zombie_watch, node_id}) do
      [{_, data}] -> Map.get(data, :check_count, 0)
      _ -> 0
    end
  end
  
  defp isolate_node(node_id, reason) do
    # Network isolation steps
    Task.start(fn ->
      # 1. Block all traffic to/from node
      add_firewall_rule(:block, node_id)
      
      # 2. Revoke authentication tokens
      revoke_node_credentials(node_id)
      
      # 3. Terminate active connections
      terminate_node_connections(node_id)
      
      # 4. Snapshot node state for forensics
      capture_node_snapshot(node_id, reason)
    end)
  end
  
  defp add_firewall_rule(action, node_id) do
    # Add firewall rule to block node
    Logger.info("Adding firewall rule: #{action} #{node_id}")
    # Implementation would interact with actual firewall
  end
  
  defp revoke_node_credentials(node_id) do
    # Revoke all credentials for the node
    Logger.info("Revoking credentials for node: #{node_id}")
    # Implementation would interact with auth system
  end
  
  defp terminate_node_connections(node_id) do
    # Force close all connections
    Logger.info("Terminating connections for node: #{node_id}")
    # Implementation would interact with connection manager
  end
  
  defp capture_node_snapshot(node_id, reason) do
    # Capture forensic snapshot
    Logger.info("Capturing snapshot for node: #{node_id}, reason: #{inspect(reason)}")
    # Implementation would trigger snapshot process
  end
  
  defp update_routing_for_quarantine(node_id) do
    # Remove quarantined node from all routes
    # Update load balancer configuration
    # Redistribute traffic to healthy nodes
    :ok
  end
  
  defp notify_quarantine(node_id, reason) do
    alert = %{
      type: :node_quarantine,
      severity: :critical,
      node_id: node_id,
      reason: reason,
      timestamp: DateTime.utc_now(),
      actions_taken: [
        :traffic_blocked,
        :credentials_revoked,
        :connections_terminated,
        :snapshot_captured
      ]
    }
    
    # Send to security team
    SecurityAlert.send(alert)
  end
  
  defp scan_for_zombies(state) do
    # Get all active nodes
    active_nodes = get_active_nodes()
    
    # Check each node
    Enum.each(active_nodes, fn node_id ->
      Task.start(fn ->
        {:ok, result} = check_zombie(node_id)
        
        if result.zombie_probability > 0.7 do
          Logger.warn("Potential zombie detected: #{node_id} (#{result.zombie_probability})")
        end
      end)
    end)
  end
  
  defp get_active_nodes do
    # In production, get from service registry
    ["node_1", "node_2", "node_3", "node_4", "node_5"]
  end
  
  defp check_component_health(state) do
    components = [
      {:router, state.router},
      {:zombie_detector, state.zombie_detector},
      {:traffic_analyzer, state.traffic_analyzer}
    ]
    
    Enum.each(components, fn {name, pid} ->
      if pid && Process.alive?(pid) do
        Logger.debug("Component #{name} is healthy")
      else
        Logger.error("Component #{name} is down!")
      end
    end)
  end
  
  defp get_component_status(nil), do: %{status: :not_initialized}
  defp get_component_status(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      %{status: :active, pid: pid}
    else
      %{status: :dead, pid: pid}
    end
  end
  
  defp init_metrics do
    %{
      routes_processed: 0,
      routes_blocked: 0,
      zombies_detected: 0,
      nodes_quarantined: 0,
      traffic_analyzed_gb: 0,
      anomalies_detected: 0,
      avg_route_time_ms: 0
    }
  end
  
  defp get_current_metrics(state) do
    # Add real-time metrics
    Map.merge(state.metrics, %{
      active_routes: :ets.info(:network_routes, :size),
      traffic_stats: get_latest_traffic_stats(),
      zombie_watches: :ets.info(:zombie_watch, :size)
    })
  end
  
  defp get_latest_traffic_stats do
    case :ets.lookup(:traffic_stats, {:stats, :latest}) do
      [{_, stats}] -> stats
      _ -> %{}
    end
  end
  
  defp calculate_network_health(state) do
    factors = [
      # Components running
      {state.router != nil, 0.2},
      {state.zombie_detector != nil, 0.2},
      {state.traffic_analyzer != nil, 0.2},
      
      # No quarantined nodes is good
      {MapSet.size(state.quarantined_nodes) == 0, 0.2},
      
      # Low anomaly rate
      {get_anomaly_rate(state) < 0.05, 0.2}
    ]
    
    Enum.reduce(factors, 0.0, fn {condition, weight}, acc ->
      if condition, do: acc + weight * 100, else: acc
    end)
  end
  
  defp get_anomaly_rate(state) do
    if state.metrics.routes_processed > 0 do
      state.metrics.anomalies_detected / state.metrics.routes_processed
    else
      0.0
    end
  end
  
  defp schedule_health_check do
    Process.send_after(self(), :health_check, :timer.seconds(60))
  end
  
  defp schedule_zombie_scan do
    Process.send_after(self(), :zombie_scan, :timer.seconds(30))
  end
end

# Sub-modules for network components

defmodule VsmSecurity.Z3N.Network.Router do
  @moduledoc """
  Zone-aware routing engine
  """
  
  use GenServer
  
  def start_link(routing_table) do
    GenServer.start_link(__MODULE__, routing_table)
  end
  
  def init(routing_table) do
    {:ok, %{table: routing_table, cache: %{}}}
  end
  
  # Implementation details...
end

defmodule VsmSecurity.Z3N.Network.ZombieDetector do
  @moduledoc """
  Zombie node detection system
  """
  
  use GenServer
  
  @zombie_indicators [
    :repetitive_patterns,
    :command_control_traffic,
    :unusual_timing,
    :resource_exhaustion,
    :lateral_movement,
    :data_exfiltration,
    :privilege_escalation
  ]
  
  def start_link(thresholds) do
    GenServer.start_link(__MODULE__, thresholds)
  end
  
  def init(thresholds) do
    {:ok, %{thresholds: thresholds, history: %{}}}
  end
  
  def analyze(pid, node_id, metrics) do
    GenServer.call(pid, {:analyze, node_id, metrics})
  end
  
  def handle_call({:analyze, node_id, metrics}, _from, state) do
    # Analyze metrics for zombie indicators
    indicators = detect_indicators(metrics, state.thresholds)
    
    # Calculate zombie probability
    probability = calculate_zombie_probability(indicators, metrics)
    
    # Update history
    new_state = update_history(state, node_id, indicators)
    
    result = %{
      node_id: node_id,
      zombie_probability: probability,
      indicators: indicators,
      recommendation: determine_action(probability),
      details: analyze_patterns(node_id, new_state.history)
    }
    
    {:reply, result, new_state}
  end
  
  defp detect_indicators(metrics, thresholds) do
    indicators = []
    
    # High resource usage
    if metrics.cpu_usage > thresholds.cpu_usage do
      indicators = [:resource_exhaustion | indicators]
    end
    
    # Repetitive patterns
    if :repetitive_requests in metrics.patterns do
      indicators = [:repetitive_patterns | indicators]
    end
    
    # Lateral movement
    if :lateral_movement in metrics.patterns do
      indicators = [:lateral_movement | indicators]
    end
    
    # Network anomalies
    if metrics.error_rate > 0.1 do
      indicators = [:unusual_timing | indicators]
    end
    
    indicators
  end
  
  defp calculate_zombie_probability(indicators, metrics) do
    base_score = length(indicators) * 0.15
    
    # Adjust based on severity
    severity_multiplier = cond do
      :lateral_movement in indicators -> 1.5
      :command_control_traffic in indicators -> 1.4
      :data_exfiltration in indicators -> 1.3
      true -> 1.0
    end
    
    # Consider resource usage
    resource_factor = (metrics.cpu_usage + metrics.memory_usage) / 200.0
    
    probability = base_score * severity_multiplier * (1 + resource_factor)
    min(probability, 1.0)
  end
  
  defp determine_action(probability) do
    cond do
      probability >= 0.9 -> :quarantine_immediately
      probability >= 0.7 -> :isolate_and_monitor
      probability >= 0.5 -> :enhanced_monitoring
      probability >= 0.3 -> :monitor
      true -> :normal
    end
  end
  
  defp update_history(state, node_id, indicators) do
    history_entry = %{
      timestamp: System.system_time(),
      indicators: indicators
    }
    
    node_history = Map.get(state.history, node_id, [])
    new_history = [history_entry | node_history] |> Enum.take(100)
    
    %{state | history: Map.put(state.history, node_id, new_history)}
  end
  
  defp analyze_patterns(node_id, history) do
    node_history = Map.get(history, node_id, [])
    
    %{
      pattern_frequency: calculate_pattern_frequency(node_history),
      trend: detect_trend(node_history),
      persistence: calculate_persistence(node_history)
    }
  end
  
  defp calculate_pattern_frequency(history) do
    history
    |> Enum.flat_map(& &1.indicators)
    |> Enum.frequencies()
  end
  
  defp detect_trend(history) do
    recent = Enum.take(history, 10)
    older = Enum.slice(history, 10, 10)
    
    recent_count = Enum.reduce(recent, 0, fn h, acc -> 
      acc + length(h.indicators)
    end)
    
    older_count = Enum.reduce(older, 0, fn h, acc -> 
      acc + length(h.indicators)
    end)
    
    cond do
      recent_count > older_count * 1.5 -> :increasing
      recent_count < older_count * 0.5 -> :decreasing
      true -> :stable
    end
  end
  
  defp calculate_persistence(history) do
    # How long has the node shown zombie indicators?
    if length(history) > 0 do
      first = List.last(history)
      last = List.first(history)
      
      duration = (last.timestamp - first.timestamp) / 1_000_000_000  # Convert to seconds
      indicator_count = length(Enum.flat_map(history, & &1.indicators))
      
      %{
        duration_seconds: duration,
        total_indicators: indicator_count,
        indicators_per_minute: indicator_count / max(duration / 60, 1)
      }
    else
      %{duration_seconds: 0, total_indicators: 0, indicators_per_minute: 0}
    end
  end
end

defmodule VsmSecurity.Z3N.Network.TrafficAnalyzer do
  @moduledoc """
  Real-time traffic analysis engine
  """
  
  use GenServer
  
  def start_link do
    GenServer.start_link(__MODULE__, [])
  end
  
  def init(_) do
    {:ok, %{
      window: :queue.new(),
      window_size: 1000,
      patterns: init_patterns()
    }}
  end
  
  def analyze(pid, traffic_data) do
    GenServer.call(pid, {:analyze, traffic_data})
  end
  
  def handle_call({:analyze, traffic_data}, _from, state) do
    # Update sliding window
    new_window = update_window(state.window, traffic_data, state.window_size)
    
    # Perform analysis
    analysis = %{
      packet_count: traffic_data.packet_count,
      byte_count: traffic_data.byte_count,
      protocols: analyze_protocols(traffic_data),
      top_sources: find_top_talkers(traffic_data.sources),
      top_destinations: find_top_destinations(traffic_data.destinations),
      requests_per_second: calculate_rps(new_window),
      unique_destinations: count_unique_destinations(new_window),
      outbound_bytes: calculate_outbound_bytes(traffic_data),
      patterns: match_patterns(traffic_data, state.patterns),
      risk_score: calculate_risk_score(traffic_data)
    }
    
    {:reply, analysis, %{state | window: new_window}}
  end
  
  defp init_patterns do
    %{
      ddos: ~r/SYN.*flood/i,
      sql_injection: ~r/(\bUNION\b|\bSELECT\b.*\bFROM\b|\bDROP\b.*\bTABLE\b)/i,
      xss: ~r/<script.*?>.*?<\/script>/i,
      port_scan: ~r/sequential.*port.*access/i
    }
  end
  
  defp update_window(window, data, max_size) do
    new_window = :queue.in(data, window)
    
    if :queue.len(new_window) > max_size do
      {_, trimmed} = :queue.out(new_window)
      trimmed
    else
      new_window
    end
  end
  
  defp analyze_protocols(traffic_data) do
    traffic_data.protocols
    |> Enum.group_by(& &1)
    |> Enum.map(fn {proto, list} -> {proto, length(list)} end)
    |> Enum.into(%{})
  end
  
  defp find_top_talkers(sources, limit \\ 10) do
    sources
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_, count} -> -count end)
    |> Enum.take(limit)
  end
  
  defp find_top_destinations(destinations, limit \\ 10) do
    destinations
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_, count} -> -count end)
    |> Enum.take(limit)
  end
  
  defp calculate_rps(window) do
    window_list = :queue.to_list(window)
    
    if length(window_list) > 0 do
      total_requests = Enum.reduce(window_list, 0, fn data, acc ->
        acc + data.packet_count
      end)
      
      # Assume each entry represents 1 second
      total_requests / max(length(window_list), 1)
    else
      0
    end
  end
  
  defp count_unique_destinations(window) do
    window
    |> :queue.to_list()
    |> Enum.flat_map(& &1.destinations)
    |> Enum.uniq()
    |> length()
  end
  
  defp calculate_outbound_bytes(traffic_data) do
    Map.get(traffic_data, :outbound_bytes, 0)
  end
  
  defp match_patterns(traffic_data, patterns) do
    payload = Map.get(traffic_data, :payload_sample, "")
    
    Enum.reduce(patterns, [], fn {name, pattern}, matches ->
      if Regex.match?(pattern, payload) do
        [name | matches]
      else
        matches
      end
    end)
  end
  
  defp calculate_risk_score(traffic_data) do
    factors = [
      {traffic_data.packet_count > 10000, 0.2},
      {traffic_data.byte_count > 1_000_000, 0.2},
      {length(traffic_data.destinations) > 50, 0.3},
      {traffic_data.error_count > 100, 0.3}
    ]
    
    Enum.reduce(factors, 0.0, fn {condition, weight}, score ->
      if condition, do: score + weight, else: score
    end)
  end
end