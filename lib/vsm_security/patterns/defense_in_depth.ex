defmodule VsmSecurity.Patterns.DefenseInDepth do
  @moduledoc """
  Implements Defense in Depth security pattern with multiple layers of protection.
  
  This pattern ensures that if one security layer is compromised, additional layers
  provide continued protection. Integrates with Z3N architecture for zone-based
  defense layers.
  """
  
  use GenServer
  require Logger
  
  alias VsmSecurity.Z3N.{Zone, Zones, Network}
  alias VsmSecurity.Telemetry
  
  @type layer :: %{
    name: String.t(),
    type: :perimeter | :network | :host | :application | :data,
    checks: list(function()),
    zone: atom(),
    severity: :critical | :high | :medium | :low
  }
  
  @type defense_result :: {:ok, :passed} | {:blocked, String.t(), list(String.t())}
  
  # Client API
  
  @doc """
  Starts the Defense in Depth service.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Validates a request through all defense layers.
  """
  @spec validate_request(map()) :: defense_result()
  def validate_request(request) do
    GenServer.call(__MODULE__, {:validate_request, request})
  end
  
  @doc """
  Adds a new defense layer dynamically.
  """
  @spec add_layer(layer()) :: :ok | {:error, term()}
  def add_layer(layer) do
    GenServer.call(__MODULE__, {:add_layer, layer})
  end
  
  @doc """
  Gets current defense metrics.
  """
  @spec get_metrics() :: map()
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end
  
  # Server Callbacks
  
  @impl true
  def init(_opts) do
    Process.flag(:trap_exit, true)
    
    state = %{
      layers: initialize_default_layers(),
      metrics: %{
        total_requests: 0,
        blocked_requests: 0,
        passed_requests: 0,
        layer_blocks: %{},
        performance: %{}
      },
      failover_strategy: :progressive
    }
    
    {:ok, state}
  end
  
  @impl true
  def handle_call({:validate_request, request}, _from, state) do
    start_time = System.monotonic_time(:microsecond)
    
    # Validate through all layers progressively
    result = validate_through_layers(request, state.layers, state.failover_strategy)
    
    # Update metrics
    new_state = update_metrics(state, result, start_time)
    
    # Emit telemetry
    emit_validation_telemetry(result, new_state)
    
    {:reply, result, new_state}
  end
  
  @impl true
  def handle_call({:add_layer, layer}, _from, state) do
    case validate_layer(layer) do
      :ok ->
        new_layers = insert_layer_by_priority(state.layers, layer)
        {:reply, :ok, %{state | layers: new_layers}}
      
      {:error, reason} = error ->
        {:reply, error, state}
    end
  end
  
  @impl true
  def handle_call(:get_metrics, _from, state) do
    {:reply, state.metrics, state}
  end
  
  # Private Functions
  
  defp initialize_default_layers do
    [
      # Perimeter Layer (Zero Zone)
      %{
        name: "perimeter_firewall",
        type: :perimeter,
        zone: :zero,
        severity: :critical,
        checks: [
          &check_ip_whitelist/1,
          &check_geo_restrictions/1,
          &check_rate_limits/1
        ]
      },
      
      # Network Layer (Zombie Zone)
      %{
        name: "network_ids",
        type: :network,
        zone: :zombie,
        severity: :high,
        checks: [
          &check_packet_anomalies/1,
          &check_protocol_compliance/1,
          &check_traffic_patterns/1
        ]
      },
      
      # Host Layer (Zen Zone)
      %{
        name: "host_protection",
        type: :host,
        zone: :zen,
        severity: :high,
        checks: [
          &check_system_integrity/1,
          &check_process_behavior/1,
          &check_file_access/1
        ]
      },
      
      # Application Layer (Zen Zone)
      %{
        name: "app_security",
        type: :application,
        zone: :zen,
        severity: :medium,
        checks: [
          &check_input_validation/1,
          &check_authentication/1,
          &check_authorization/1
        ]
      },
      
      # Data Layer (Zen Zone)
      %{
        name: "data_protection",
        type: :data,
        zone: :zen,
        severity: :critical,
        checks: [
          &check_encryption/1,
          &check_data_integrity/1,
          &check_access_control/1
        ]
      }
    ]
  end
  
  defp validate_through_layers(request, layers, strategy) do
    # Track which layers blocked the request
    blocked_layers = []
    
    result = Enum.reduce_while(layers, {:ok, :passed}, fn layer, acc ->
      case validate_layer_checks(request, layer) do
        {:ok, :passed} ->
          {:cont, acc}
          
        {:blocked, reason} ->
          blocked_layers = [layer.name | blocked_layers]
          
          case strategy do
            :progressive ->
              # Continue checking other layers even if blocked
              {:cont, {:blocked, "Defense in depth violation", blocked_layers}}
              
            :fail_fast ->
              # Stop at first block
              {:halt, {:blocked, reason, [layer.name]}}
              
            :adaptive ->
              # Decide based on severity
              if layer.severity in [:critical, :high] do
                {:halt, {:blocked, reason, [layer.name]}}
              else
                {:cont, {:blocked, "Multiple security concerns", blocked_layers}}
              end
          end
      end
    end)
    
    case result do
      {:ok, :passed} -> result
      {:blocked, _, _} = blocked -> 
        # Add all blocked layers to the result
        {:blocked, elem(blocked, 1), Enum.reverse(blocked_layers)}
    end
  end
  
  defp validate_layer_checks(request, layer) do
    # Check if zone is active
    zone_active? = Zone.active?(layer.zone)
    
    if zone_active? do
      # Run all checks for this layer
      results = Enum.map(layer.checks, fn check ->
        try do
          check.(request)
        rescue
          e -> {:error, Exception.message(e)}
        end
      end)
      
      # If any check fails, the layer blocks
      case Enum.find(results, fn r -> match?({:blocked, _}, r) end) do
        nil -> {:ok, :passed}
        {:blocked, reason} -> {:blocked, "#{layer.name}: #{reason}"}
      end
    else
      # Zone inactive, skip layer
      {:ok, :passed}
    end
  end
  
  # Security Check Functions
  
  defp check_ip_whitelist(%{ip: ip}) do
    whitelist = Application.get_env(:vsm_security, :ip_whitelist, [])
    
    if ip in whitelist or whitelist == [] do
      {:ok, :passed}
    else
      {:blocked, "IP not whitelisted"}
    end
  end
  defp check_ip_whitelist(_), do: {:ok, :passed}
  
  defp check_geo_restrictions(%{geo: geo}) do
    blocked_countries = Application.get_env(:vsm_security, :blocked_countries, [])
    
    if geo[:country] in blocked_countries do
      {:blocked, "Geographic restriction"}
    else
      {:ok, :passed}
    end
  end
  defp check_geo_restrictions(_), do: {:ok, :passed}
  
  defp check_rate_limits(%{ip: ip}) do
    # Simple rate limit check (would use ETS or Redis in production)
    {:ok, :passed}
  end
  defp check_rate_limits(_), do: {:ok, :passed}
  
  defp check_packet_anomalies(%{packet_data: data}) do
    # Check for malformed packets, unusual sizes, etc.
    if byte_size(data) > 65_535 do
      {:blocked, "Packet size anomaly"}
    else
      {:ok, :passed}
    end
  end
  defp check_packet_anomalies(_), do: {:ok, :passed}
  
  defp check_protocol_compliance(%{protocol: protocol}) do
    allowed_protocols = [:http, :https, :websocket]
    
    if protocol in allowed_protocols do
      {:ok, :passed}
    else
      {:blocked, "Protocol not allowed"}
    end
  end
  defp check_protocol_compliance(_), do: {:ok, :passed}
  
  defp check_traffic_patterns(request) do
    # Would analyze traffic patterns for DDoS, scanning, etc.
    {:ok, :passed}
  end
  
  defp check_system_integrity(_request) do
    # Would check system file integrity, running processes, etc.
    {:ok, :passed}
  end
  
  defp check_process_behavior(_request) do
    # Would monitor process behavior for anomalies
    {:ok, :passed}
  end
  
  defp check_file_access(%{file_access: files}) do
    restricted_paths = ["/etc", "/sys", "/proc"]
    
    if Enum.any?(files, fn f -> Enum.any?(restricted_paths, &String.starts_with?(f, &1)) end) do
      {:blocked, "Restricted file access attempt"}
    else
      {:ok, :passed}
    end
  end
  defp check_file_access(_), do: {:ok, :passed}
  
  defp check_input_validation(%{input: input}) do
    # Check for SQL injection, XSS, etc.
    dangerous_patterns = ["<script", "';DROP", "OR 1=1", "../.."]
    
    if Enum.any?(dangerous_patterns, &String.contains?(input, &1)) do
      {:blocked, "Malicious input detected"}
    else
      {:ok, :passed}
    end
  end
  defp check_input_validation(_), do: {:ok, :passed}
  
  defp check_authentication(%{auth_token: token}) do
    # Would validate JWT or session token
    if token && String.length(token) > 0 do
      {:ok, :passed}
    else
      {:blocked, "Authentication required"}
    end
  end
  defp check_authentication(_), do: {:blocked, "No authentication provided"}
  
  defp check_authorization(%{user_role: role, requested_resource: resource}) do
    # Simple RBAC check
    allowed_resources = %{
      admin: :all,
      user: ["profile", "public"],
      guest: ["public"]
    }
    
    case allowed_resources[role] do
      :all -> {:ok, :passed}
      allowed when is_list(allowed) ->
        if resource in allowed do
          {:ok, :passed}
        else
          {:blocked, "Unauthorized resource access"}
        end
      _ -> {:blocked, "Unknown role"}
    end
  end
  defp check_authorization(_), do: {:ok, :passed}
  
  defp check_encryption(%{encrypted: true}), do: {:ok, :passed}
  defp check_encryption(%{encrypted: false}), do: {:blocked, "Encryption required"}
  defp check_encryption(_), do: {:ok, :passed}
  
  defp check_data_integrity(%{checksum: provided, data: data}) do
    calculated = :crypto.hash(:sha256, data) |> Base.encode16()
    
    if provided == calculated do
      {:ok, :passed}
    else
      {:blocked, "Data integrity check failed"}
    end
  end
  defp check_data_integrity(_), do: {:ok, :passed}
  
  defp check_access_control(%{access_level: level, data_classification: classification}) do
    # Check if access level matches data classification
    required_levels = %{
      public: [:any],
      internal: [:employee, :admin],
      confidential: [:manager, :admin],
      secret: [:admin]
    }
    
    allowed = Map.get(required_levels, classification, [:admin])
    
    if level in allowed or :any in allowed do
      {:ok, :passed}
    else
      {:blocked, "Insufficient access level"}
    end
  end
  defp check_access_control(_), do: {:ok, :passed}
  
  defp validate_layer(layer) do
    required_fields = [:name, :type, :zone, :severity, :checks]
    
    missing = required_fields -- Map.keys(layer)
    
    if missing == [] do
      :ok
    else
      {:error, "Missing required fields: #{inspect(missing)}"}
    end
  end
  
  defp insert_layer_by_priority(layers, new_layer) do
    # Insert based on type priority
    priority_order = [:perimeter, :network, :host, :application, :data]
    
    Enum.sort_by([new_layer | layers], fn layer ->
      Enum.find_index(priority_order, &(&1 == layer.type)) || 999
    end)
  end
  
  defp update_metrics(state, result, start_time) do
    elapsed = System.monotonic_time(:microsecond) - start_time
    
    metrics = state.metrics
    |> Map.update!(:total_requests, &(&1 + 1))
    |> update_result_metrics(result)
    |> update_performance_metrics(elapsed)
    
    %{state | metrics: metrics}
  end
  
  defp update_result_metrics(metrics, {:ok, :passed}) do
    Map.update!(metrics, :passed_requests, &(&1 + 1))
  end
  
  defp update_result_metrics(metrics, {:blocked, _, blocked_layers}) do
    metrics
    |> Map.update!(:blocked_requests, &(&1 + 1))
    |> Map.update!(:layer_blocks, fn blocks ->
      Enum.reduce(blocked_layers, blocks, fn layer, acc ->
        Map.update(acc, layer, 1, &(&1 + 1))
      end)
    end)
  end
  
  defp update_performance_metrics(metrics, elapsed) do
    Map.update(metrics, :performance, %{avg_response_time: elapsed}, fn perf ->
      count = Map.get(perf, :count, 0) + 1
      avg = Map.get(perf, :avg_response_time, 0)
      new_avg = ((avg * (count - 1)) + elapsed) / count
      
      Map.merge(perf, %{
        count: count,
        avg_response_time: new_avg,
        last_response_time: elapsed
      })
    end)
  end
  
  defp emit_validation_telemetry(result, state) do
    event = case result do
      {:ok, :passed} -> [:defense_in_depth, :request, :passed]
      {:blocked, _, _} -> [:defense_in_depth, :request, :blocked]
    end
    
    Telemetry.execute(event, state.metrics, %{result: result})
  end
end