defmodule VsmSecurity.Patterns.ThreatIntelligence do
  @moduledoc """
  Implements Threat Intelligence pattern with real-time threat feeds,
  pattern matching, and predictive analysis.
  
  Features:
  - Multiple threat feed integration
  - Real-time pattern matching using Bloom filters
  - Predictive threat analysis using neural patterns
  - Automated threat response coordination
  
  Integrates with Z3N architecture for zone-specific threat detection.
  """
  
  use GenServer
  require Logger
  
  alias VsmSecurity.Z3N.{Zone, Neural}
  alias VsmSecurity.BloomFilters.ThreatFilter
  alias VsmSecurity.Telemetry
  
  @type threat_indicator :: %{
    type: :ip | :domain | :hash | :pattern | :behavior,
    value: String.t() | map(),
    severity: :low | :medium | :high | :critical,
    confidence: float(),
    source: String.t(),
    timestamp: DateTime.t(),
    ttl: integer()
  }
  
  @type threat_feed :: %{
    name: String.t(),
    url: String.t() | nil,
    type: :osint | :commercial | :internal | :community,
    format: :stix | :json | :csv | :custom,
    enabled: boolean(),
    update_interval: integer()
  }
  
  @type threat_analysis :: %{
    matched: boolean(),
    indicators: list(threat_indicator()),
    risk_score: float(),
    predicted_impact: atom(),
    recommended_actions: list(atom())
  }
  
  # Client API
  
  @doc """
  Starts the Threat Intelligence service.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Analyzes an entity (IP, domain, hash, etc.) against threat intelligence.
  """
  @spec analyze_threat(map()) :: {:ok, threat_analysis()} | {:error, term()}
  def analyze_threat(entity) do
    GenServer.call(__MODULE__, {:analyze_threat, entity}, 10_000)
  end
  
  @doc """
  Adds a new threat indicator to the intelligence database.
  """
  @spec add_indicator(threat_indicator()) :: :ok | {:error, term()}
  def add_indicator(indicator) do
    GenServer.call(__MODULE__, {:add_indicator, indicator})
  end
  
  @doc """
  Updates threat feeds manually.
  """
  @spec update_feeds() :: :ok
  def update_feeds do
    GenServer.cast(__MODULE__, :update_feeds)
  end
  
  @doc """
  Gets predictive threat analysis for a time window.
  """
  @spec predict_threats(integer()) :: {:ok, map()} | {:error, term()}
  def predict_threats(hours_ahead \\ 24) do
    GenServer.call(__MODULE__, {:predict_threats, hours_ahead})
  end
  
  @doc """
  Gets current threat intelligence metrics.
  """
  @spec get_metrics() :: map()
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end
  
  # Server Callbacks
  
  @impl true
  def init(_opts) do
    Process.flag(:trap_exit, true)
    
    # Initialize threat feeds
    feeds = initialize_threat_feeds()
    
    # Schedule periodic feed updates
    schedule_feed_updates(feeds)
    
    # Initialize neural threat predictor
    {:ok, neural_pid} = Neural.start_link(model: :threat_predictor)
    
    state = %{
      feeds: feeds,
      indicators: %{
        ip: %{},
        domain: %{},
        hash: %{},
        pattern: %{},
        behavior: %{}
      },
      bloom_filters: initialize_bloom_filters(),
      neural_predictor: neural_pid,
      pattern_cache: :ets.new(:threat_patterns, [:set, :protected]),
      metrics: %{
        total_indicators: 0,
        threats_detected: 0,
        feeds_updated: 0,
        predictions_made: 0,
        false_positives: 0,
        true_positives: 0
      }
    }
    
    # Load initial threat data
    GenServer.cast(self(), :update_feeds)
    
    {:ok, state}
  end
  
  @impl true
  def handle_call({:analyze_threat, entity}, _from, state) do
    analysis = perform_threat_analysis(entity, state)
    
    # Update metrics
    new_state = update_analysis_metrics(state, analysis)
    
    # Train neural model with result
    train_neural_model(new_state.neural_predictor, entity, analysis)
    
    # Emit telemetry
    emit_threat_telemetry(analysis, new_state)
    
    {:reply, {:ok, analysis}, new_state}
  end
  
  @impl true
  def handle_call({:add_indicator, indicator}, _from, state) do
    case validate_indicator(indicator) do
      :ok ->
        new_state = store_indicator(state, indicator)
        {:reply, :ok, new_state}
        
      {:error, _} = error ->
        {:reply, error, state}
    end
  end
  
  @impl true
  def handle_call({:predict_threats, hours_ahead}, _from, state) do
    prediction = perform_threat_prediction(hours_ahead, state)
    
    new_state = update_in(state, [:metrics, :predictions_made], &(&1 + 1))
    
    {:reply, {:ok, prediction}, new_state}
  end
  
  @impl true
  def handle_call(:get_metrics, _from, state) do
    {:reply, state.metrics, state}
  end
  
  @impl true
  def handle_cast(:update_feeds, state) do
    new_state = update_all_feeds(state)
    {:noreply, new_state}
  end
  
  @impl true
  def handle_info({:update_feed, feed_name}, state) do
    new_state = update_single_feed(state, feed_name)
    
    # Reschedule next update
    feed = Enum.find(state.feeds, &(&1.name == feed_name))
    if feed && feed.enabled do
      Process.send_after(self(), {:update_feed, feed_name}, feed.update_interval)
    end
    
    {:noreply, new_state}
  end
  
  # Private Functions
  
  defp initialize_threat_feeds do
    [
      %{
        name: "abuse_ipdb",
        url: "https://api.abuseipdb.com/api/v2/blacklist",
        type: :osint,
        format: :json,
        enabled: true,
        update_interval: 3_600_000 # 1 hour
      },
      %{
        name: "emerging_threats",
        url: "https://rules.emergingthreats.net/open/",
        type: :osint,
        format: :custom,
        enabled: true,
        update_interval: 21_600_000 # 6 hours
      },
      %{
        name: "internal_ioc",
        url: nil, # Internal source
        type: :internal,
        format: :json,
        enabled: true,
        update_interval: 300_000 # 5 minutes
      },
      %{
        name: "threat_exchange",
        url: "https://threatexchange.fb.com/",
        type: :community,
        format: :stix,
        enabled: false, # Requires API key
        update_interval: 1_800_000 # 30 minutes
      },
      %{
        name: "malware_bazaar",
        url: "https://mb-api.abuse.ch/api/v1/",
        type: :osint,
        format: :json,
        enabled: true,
        update_interval: 7_200_000 # 2 hours
      }
    ]
  end
  
  defp initialize_bloom_filters do
    %{
      ip: ThreatFilter.new("threat_ip", 10_000_000),
      domain: ThreatFilter.new("threat_domain", 5_000_000),
      hash: ThreatFilter.new("threat_hash", 20_000_000)
    }
  end
  
  defp schedule_feed_updates(feeds) do
    Enum.each(feeds, fn feed ->
      if feed.enabled do
        Process.send_after(self(), {:update_feed, feed.name}, feed.update_interval)
      end
    end)
  end
  
  defp perform_threat_analysis(entity, state) do
    # Quick check with Bloom filters first
    quick_match = check_bloom_filters(entity, state.bloom_filters)
    
    if quick_match do
      # Detailed analysis if Bloom filter indicates possible match
      indicators = find_matching_indicators(entity, state.indicators)
      
      # Pattern-based analysis
      pattern_matches = analyze_patterns(entity, state.pattern_cache)
      
      # Behavioral analysis
      behavior_score = analyze_behavior(entity, state)
      
      # Neural prediction
      prediction = get_neural_prediction(entity, state.neural_predictor)
      
      # Combine all analysis
      build_threat_analysis(indicators, pattern_matches, behavior_score, prediction)
    else
      # No quick match, minimal analysis
      %{
        matched: false,
        indicators: [],
        risk_score: 0.0,
        predicted_impact: :none,
        recommended_actions: []
      }
    end
  end
  
  defp check_bloom_filters(entity, filters) do
    cond do
      entity[:ip] && ThreatFilter.contains?(filters.ip, entity.ip) -> true
      entity[:domain] && ThreatFilter.contains?(filters.domain, entity.domain) -> true
      entity[:hash] && ThreatFilter.contains?(filters.hash, entity.hash) -> true
      true -> false
    end
  end
  
  defp find_matching_indicators(entity, all_indicators) do
    indicators = []
    
    # Check each indicator type
    indicators = 
      if entity[:ip] do
        case Map.get(all_indicators.ip, entity.ip) do
          nil -> indicators
          indicator -> [indicator | indicators]
        end
      else
        indicators
      end
    
    indicators = 
      if entity[:domain] do
        case Map.get(all_indicators.domain, entity.domain) do
          nil -> indicators
          indicator -> [indicator | indicators]
        end
      else
        indicators
      end
    
    indicators = 
      if entity[:hash] do
        case Map.get(all_indicators.hash, entity.hash) do
          nil -> indicators
          indicator -> [indicator | indicators]
        end
      else
        indicators
      end
    
    # Check pattern-based indicators
    pattern_indicators = 
      all_indicators.pattern
      |> Map.values()
      |> Enum.filter(&pattern_matches_entity?(&1, entity))
    
    indicators ++ pattern_indicators
  end
  
  defp pattern_matches_entity?(pattern_indicator, entity) do
    pattern = pattern_indicator.value
    
    case pattern[:type] do
      :regex ->
        regex = Regex.compile!(pattern[:expression])
        entity_string = inspect(entity)
        Regex.match?(regex, entity_string)
        
      :behavior ->
        check_behavior_pattern(pattern[:rules], entity)
        
      _ ->
        false
    end
  end
  
  defp check_behavior_pattern(rules, entity) do
    # Simple rule engine for behavior patterns
    Enum.all?(rules, fn rule ->
      case rule do
        {:field, field, :equals, value} ->
          get_in(entity, field) == value
          
        {:field, field, :contains, value} ->
          field_value = get_in(entity, field)
          field_value && String.contains?(to_string(field_value), value)
          
        {:field, field, :greater_than, value} ->
          field_value = get_in(entity, field)
          field_value && field_value > value
          
        _ ->
          false
      end
    end)
  end
  
  defp analyze_patterns(entity, pattern_cache) do
    # Load cached patterns
    patterns = :ets.tab2list(pattern_cache)
    
    # Check entity against each pattern
    Enum.reduce(patterns, [], fn {pattern_id, pattern}, matches ->
      if matches_pattern?(entity, pattern) do
        [{pattern_id, pattern} | matches]
      else
        matches
      end
    end)
  end
  
  defp matches_pattern?(entity, pattern) do
    # Pattern matching logic
    case pattern.type do
      :sequence ->
        check_sequence_pattern(entity, pattern.sequence)
        
      :frequency ->
        check_frequency_pattern(entity, pattern.threshold)
        
      :correlation ->
        check_correlation_pattern(entity, pattern.correlations)
        
      _ ->
        false
    end
  end
  
  defp check_sequence_pattern(entity, sequence) do
    # Check if entity follows a known attack sequence
    entity[:events] && Enum.any?(entity.events, fn event_seq ->
      event_seq == sequence
    end)
  end
  
  defp check_frequency_pattern(entity, threshold) do
    # Check if entity shows high-frequency behavior
    entity[:request_count] && entity.request_count > threshold
  end
  
  defp check_correlation_pattern(entity, correlations) do
    # Check if entity correlates with known bad actors
    entity[:connections] && Enum.any?(entity.connections, fn conn ->
      conn in correlations
    end)
  end
  
  defp analyze_behavior(entity, state) do
    # Behavioral scoring based on various factors
    scores = [
      score_connection_behavior(entity),
      score_temporal_behavior(entity),
      score_data_transfer_behavior(entity),
      score_protocol_behavior(entity)
    ]
    
    # Average of all behavior scores
    Enum.sum(scores) / length(scores)
  end
  
  defp score_connection_behavior(entity) do
    cond do
      # Many short-lived connections (scanning behavior)
      entity[:avg_connection_duration] && entity.avg_connection_duration < 1000 -> 0.8
      
      # Connections to many different ports
      entity[:unique_ports] && entity.unique_ports > 100 -> 0.7
      
      # Normal connection pattern
      true -> 0.2
    end
  end
  
  defp score_temporal_behavior(entity) do
    cond do
      # Activity at unusual hours
      entity[:hour] && entity.hour in [0, 1, 2, 3, 4] -> 0.6
      
      # Periodic/automated behavior
      entity[:request_interval_variance] && entity.request_interval_variance < 0.1 -> 0.7
      
      # Normal temporal pattern
      true -> 0.1
    end
  end
  
  defp score_data_transfer_behavior(entity) do
    cond do
      # Large data exfiltration
      entity[:bytes_out] && entity.bytes_out > 1_000_000_000 -> 0.9
      
      # Suspicious upload/download ratio
      entity[:bytes_in] && entity[:bytes_out] && 
        entity.bytes_out / (entity.bytes_in + 1) > 10 -> 0.7
      
      # Normal data transfer
      true -> 0.1
    end
  end
  
  defp score_protocol_behavior(entity) do
    suspicious_protocols = [:tor, :ssh_tunnel, :dns_tunnel, :icmp_tunnel]
    
    cond do
      # Using suspicious protocols
      entity[:protocol] && entity.protocol in suspicious_protocols -> 0.8
      
      # Protocol anomalies
      entity[:protocol_violations] && entity.protocol_violations > 0 -> 0.6
      
      # Normal protocol usage
      true -> 0.1
    end
  end
  
  defp get_neural_prediction(entity, neural_pid) do
    # Prepare features for neural model
    features = extract_neural_features(entity)
    
    # Get prediction from neural model
    case Neural.predict(neural_pid, features) do
      {:ok, prediction} -> prediction
      {:error, _} -> %{threat_probability: 0.5, threat_type: :unknown}
    end
  end
  
  defp extract_neural_features(entity) do
    # Extract numerical features for neural network
    %{
      ip_reputation: entity[:ip_reputation] || 0.5,
      domain_age: entity[:domain_age] || 30,
      certificate_validity: entity[:cert_valid] || 1,
      connection_count: entity[:connection_count] || 0,
      bytes_transferred: entity[:bytes_total] || 0,
      unique_user_agents: entity[:unique_uas] || 1,
      request_rate: entity[:request_rate] || 0,
      geographic_distance: entity[:geo_distance] || 0
    }
  end
  
  defp build_threat_analysis(indicators, pattern_matches, behavior_score, prediction) do
    # Calculate overall risk score
    indicator_score = calculate_indicator_score(indicators)
    pattern_score = length(pattern_matches) * 0.1
    neural_score = prediction[:threat_probability] || 0.5
    
    # Weighted combination
    risk_score = 
      (indicator_score * 0.4) +
      (pattern_score * 0.2) +
      (behavior_score * 0.2) +
      (neural_score * 0.2)
    
    # Determine impact and actions
    predicted_impact = categorize_impact(risk_score, indicators)
    recommended_actions = determine_actions(risk_score, predicted_impact, indicators)
    
    %{
      matched: !Enum.empty?(indicators) || !Enum.empty?(pattern_matches),
      indicators: indicators,
      risk_score: Float.round(risk_score, 3),
      predicted_impact: predicted_impact,
      recommended_actions: recommended_actions
    }
  end
  
  defp calculate_indicator_score(indicators) do
    if Enum.empty?(indicators) do
      0.0
    else
      # Weight by severity and confidence
      total_score = Enum.reduce(indicators, 0.0, fn indicator, acc ->
        severity_weight = case indicator.severity do
          :critical -> 1.0
          :high -> 0.7
          :medium -> 0.4
          :low -> 0.2
        end
        
        acc + (severity_weight * indicator.confidence)
      end)
      
      # Normalize to 0-1 range
      min(total_score / length(indicators), 1.0)
    end
  end
  
  defp categorize_impact(risk_score, indicators) do
    # Check for specific threat types in indicators
    threat_types = indicators
    |> Enum.map(& &1[:threat_type])
    |> Enum.filter(& &1)
    |> Enum.uniq()
    
    cond do
      :ransomware in threat_types -> :data_encryption
      :apt in threat_types -> :persistent_compromise
      :ddos in threat_types -> :service_disruption
      :data_theft in threat_types -> :data_breach
      risk_score > 0.8 -> :system_compromise
      risk_score > 0.6 -> :security_incident
      risk_score > 0.4 -> :suspicious_activity
      true -> :minimal
    end
  end
  
  defp determine_actions(risk_score, impact, indicators) do
    base_actions = cond do
      risk_score > 0.8 -> [:block_immediately, :isolate_system, :alert_soc]
      risk_score > 0.6 -> [:monitor_closely, :rate_limit, :alert_analyst]
      risk_score > 0.4 -> [:log_activity, :increase_monitoring]
      true -> [:log_minimal]
    end
    
    # Add impact-specific actions
    impact_actions = case impact do
      :data_encryption -> [:backup_data, :disable_shares]
      :persistent_compromise -> [:full_scan, :credential_reset]
      :service_disruption -> [:enable_ddos_protection, :scale_resources]
      :data_breach -> [:revoke_access, :notify_compliance]
      _ -> []
    end
    
    # Add indicator-specific actions
    indicator_actions = indicators
    |> Enum.flat_map(fn indicator ->
      case indicator.type do
        :ip -> [:block_ip]
        :domain -> [:block_domain]
        :hash -> [:quarantine_file]
        _ -> []
      end
    end)
    |> Enum.uniq()
    
    Enum.uniq(base_actions ++ impact_actions ++ indicator_actions)
  end
  
  defp perform_threat_prediction(hours_ahead, state) do
    # Get historical threat data
    historical_data = get_historical_threats(state)
    
    # Neural prediction for future threats
    prediction = Neural.predict_timeline(
      state.neural_predictor,
      historical_data,
      hours_ahead
    )
    
    # Analyze trends
    trends = analyze_threat_trends(historical_data)
    
    # Combine predictions
    %{
      timeframe: hours_ahead,
      predicted_threats: prediction[:threats] || [],
      threat_probability: prediction[:probability] || 0.5,
      trending_indicators: trends[:increasing] || [],
      declining_indicators: trends[:decreasing] || [],
      emerging_patterns: find_emerging_patterns(state)
    }
  end
  
  defp get_historical_threats(state) do
    # In production, would query time-series database
    # For now, return sample data
    %{
      threat_counts: generate_sample_timeseries(),
      indicator_frequencies: %{
        ip: 245,
        domain: 132,
        hash: 567,
        pattern: 89
      }
    }
  end
  
  defp generate_sample_timeseries do
    # Generate sample threat count time series
    Enum.map(1..24, fn hour ->
      %{
        hour: hour,
        count: :rand.uniform(100),
        severity_distribution: %{
          critical: :rand.uniform(10),
          high: :rand.uniform(30),
          medium: :rand.uniform(40),
          low: :rand.uniform(20)
        }
      }
    end)
  end
  
  defp analyze_threat_trends(historical_data) do
    # Simple trend analysis
    %{
      increasing: [:botnet_activity, :phishing_campaigns],
      decreasing: [:ransomware, :cryptomining],
      stable: [:port_scanning, :brute_force]
    }
  end
  
  defp find_emerging_patterns(state) do
    # Identify new patterns not seen before
    [
      %{
        pattern: "distributed_credential_stuffing",
        first_seen: DateTime.utc_now() |> DateTime.add(-3600, :second),
        occurrence_count: 15,
        confidence: 0.7
      }
    ]
  end
  
  defp validate_indicator(indicator) do
    required_fields = [:type, :value, :severity, :source]
    
    missing = required_fields -- Map.keys(indicator)
    
    if missing == [] do
      :ok
    else
      {:error, "Missing required fields: #{inspect(missing)}"}
    end
  end
  
  defp store_indicator(state, indicator) do
    # Add to appropriate indicator map
    indicator_with_metadata = indicator
    |> Map.put(:timestamp, DateTime.utc_now())
    |> Map.put_new(:ttl, 86400) # 24 hour default TTL
    |> Map.put_new(:confidence, 0.8)
    
    # Store in appropriate map based on type
    new_indicators = case indicator.type do
      :ip ->
        put_in(state.indicators.ip[indicator.value], indicator_with_metadata)
        
      :domain ->
        put_in(state.indicators.domain[indicator.value], indicator_with_metadata)
        
      :hash ->
        put_in(state.indicators.hash[indicator.value], indicator_with_metadata)
        
      :pattern ->
        pattern_id = :crypto.strong_rand_bytes(16) |> Base.encode16()
        put_in(state.indicators.pattern[pattern_id], indicator_with_metadata)
        
      :behavior ->
        behavior_id = :crypto.strong_rand_bytes(16) |> Base.encode16()
        put_in(state.indicators.behavior[behavior_id], indicator_with_metadata)
    end
    
    # Update Bloom filter
    new_bloom_filters = case indicator.type do
      :ip ->
        ThreatFilter.add(state.bloom_filters.ip, indicator.value)
        state.bloom_filters
        
      :domain ->
        ThreatFilter.add(state.bloom_filters.domain, indicator.value)
        state.bloom_filters
        
      :hash ->
        ThreatFilter.add(state.bloom_filters.hash, indicator.value)
        state.bloom_filters
        
      _ ->
        state.bloom_filters
    end
    
    state
    |> Map.put(:indicators, new_indicators)
    |> Map.put(:bloom_filters, new_bloom_filters)
    |> update_in([:metrics, :total_indicators], &(&1 + 1))
  end
  
  defp update_all_feeds(state) do
    Enum.reduce(state.feeds, state, fn feed, acc ->
      if feed.enabled do
        update_single_feed(acc, feed.name)
      else
        acc
      end
    end)
  end
  
  defp update_single_feed(state, feed_name) do
    feed = Enum.find(state.feeds, &(&1.name == feed_name))
    
    if feed do
      Logger.info("Updating threat feed: #{feed_name}")
      
      # In production, would fetch from actual feeds
      # For now, simulate with sample data
      new_indicators = generate_sample_indicators(feed)
      
      # Store all new indicators
      new_state = Enum.reduce(new_indicators, state, &store_indicator(&2, &1))
      
      update_in(new_state, [:metrics, :feeds_updated], &(&1 + 1))
    else
      state
    end
  end
  
  defp generate_sample_indicators(feed) do
    # Generate sample indicators based on feed type
    case feed.name do
      "abuse_ipdb" ->
        Enum.map(1..10, fn _ ->
          %{
            type: :ip,
            value: generate_random_ip(),
            severity: Enum.random([:low, :medium, :high]),
            confidence: 0.7 + :rand.uniform() * 0.3,
            source: feed.name,
            threat_type: :botnet
          }
        end)
        
      "malware_bazaar" ->
        Enum.map(1..5, fn _ ->
          %{
            type: :hash,
            value: :crypto.strong_rand_bytes(32) |> Base.encode16(),
            severity: :high,
            confidence: 0.9,
            source: feed.name,
            threat_type: :malware
          }
        end)
        
      _ ->
        []
    end
  end
  
  defp generate_random_ip do
    Enum.join([
      :rand.uniform(255),
      :rand.uniform(255),
      :rand.uniform(255),
      :rand.uniform(255)
    ], ".")
  end
  
  defp train_neural_model(neural_pid, entity, analysis) do
    # Train the neural model with the analysis result
    training_data = %{
      input: extract_neural_features(entity),
      output: %{
        threat_detected: analysis.matched,
        risk_score: analysis.risk_score,
        impact: analysis.predicted_impact
      }
    }
    
    Neural.train(neural_pid, [training_data])
  end
  
  defp update_analysis_metrics(state, analysis) do
    state
    |> update_in([:metrics, :threats_detected], fn count ->
      if analysis.matched, do: count + 1, else: count
    end)
  end
  
  defp emit_threat_telemetry(analysis, state) do
    event = if analysis.matched,
      do: [:threat_intelligence, :threat, :detected],
      else: [:threat_intelligence, :threat, :clear]
    
    measurements = %{
      risk_score: analysis.risk_score,
      indicator_count: length(analysis.indicators),
      total_threats: state.metrics.threats_detected
    }
    
    metadata = %{
      predicted_impact: analysis.predicted_impact,
      recommended_actions: analysis.recommended_actions
    }
    
    Telemetry.execute(event, measurements, metadata)
  end
end