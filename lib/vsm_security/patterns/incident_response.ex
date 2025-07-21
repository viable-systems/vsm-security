defmodule VsmSecurity.Patterns.IncidentResponse do
  @moduledoc """
  Implements Incident Response pattern with automated response playbooks,
  forensics collection, and recovery procedures.
  
  Features:
  - Automated incident detection and classification
  - Response playbook execution
  - Forensic evidence collection
  - Recovery and remediation procedures
  - Post-incident analysis
  
  Integrates with Z3N architecture for zone-specific incident handling.
  """
  
  use GenServer
  require Logger
  
  alias VsmSecurity.Z3N.{Zone, Zones, Network}
  alias VsmSecurity.Patterns.{ThreatIntelligence, ZeroTrust}
  alias VsmSecurity.Telemetry
  
  @type incident :: %{
    id: String.t(),
    type: atom(),
    severity: :low | :medium | :high | :critical,
    status: :detected | :investigating | :containing | :eradicating | :recovering | :closed,
    zone: atom(),
    affected_systems: list(String.t()),
    indicators: list(map()),
    timeline: list(map()),
    responders: list(String.t()),
    playbook: String.t(),
    forensics: map()
  }
  
  @type playbook :: %{
    name: String.t(),
    type: atom(),
    severity_threshold: atom(),
    steps: list(playbook_step()),
    rollback_steps: list(playbook_step())
  }
  
  @type playbook_step :: %{
    name: String.t(),
    action: function() | {module(), atom(), list()},
    timeout: integer(),
    on_failure: :continue | :abort | :rollback,
    requires_approval: boolean()
  }
  
  @type response_result :: %{
    success: boolean(),
    incident_id: String.t(),
    actions_taken: list(String.t()),
    recovery_eta: DateTime.t() | nil,
    post_incident_tasks: list(String.t())
  }
  
  # Client API
  
  @doc """
  Starts the Incident Response service.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc """
  Reports a new incident for response.
  """
  @spec report_incident(map()) :: {:ok, String.t()} | {:error, term()}
  def report_incident(incident_data) do
    GenServer.call(__MODULE__, {:report_incident, incident_data})
  end
  
  @doc """
  Executes response for a detected incident.
  """
  @spec respond_to_incident(String.t()) :: {:ok, response_result()} | {:error, term()}
  def respond_to_incident(incident_id) do
    GenServer.call(__MODULE__, {:respond_to_incident, incident_id}, 30_000)
  end
  
  @doc """
  Updates incident status.
  """
  @spec update_incident(String.t(), map()) :: :ok | {:error, term()}
  def update_incident(incident_id, updates) do
    GenServer.call(__MODULE__, {:update_incident, incident_id, updates})
  end
  
  @doc """
  Collects forensic data for an incident.
  """
  @spec collect_forensics(String.t()) :: {:ok, map()} | {:error, term()}
  def collect_forensics(incident_id) do
    GenServer.call(__MODULE__, {:collect_forensics, incident_id}, 60_000)
  end
  
  @doc """
  Gets incident metrics and statistics.
  """
  @spec get_metrics() :: map()
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end
  
  # Server Callbacks
  
  @impl true
  def init(_opts) do
    Process.flag(:trap_exit, true)
    
    # Load playbooks
    playbooks = load_playbooks()
    
    # Initialize forensics storage
    :ets.new(:incident_forensics, [:named_table, :set, :protected])
    
    state = %{
      incidents: %{},
      active_responses: %{},
      playbooks: playbooks,
      forensic_collectors: initialize_collectors(),
      recovery_procedures: initialize_recovery_procedures(),
      metrics: %{
        total_incidents: 0,
        incidents_by_type: %{},
        incidents_by_severity: %{},
        avg_response_time: 0,
        avg_recovery_time: 0,
        successful_responses: 0,
        failed_responses: 0
      }
    }
    
    # Start incident monitoring
    Process.send_after(self(), :check_incidents, 5_000)
    
    {:ok, state}
  end
  
  @impl true
  def handle_call({:report_incident, incident_data}, _from, state) do
    # Generate incident ID
    incident_id = generate_incident_id()
    
    # Classify and enrich incident
    incident = create_incident(incident_id, incident_data, state)
    
    # Store incident
    new_state = 
      state
      |> put_in([:incidents, incident_id], incident)
      |> update_incident_metrics(incident)
    
    # Log incident
    Logger.warning("Incident reported: #{incident_id} - Type: #{incident.type}, Severity: #{incident.severity}")
    
    # Auto-respond for high/critical incidents
    if incident.severity in [:high, :critical] do
      send(self(), {:auto_respond, incident_id})
    end
    
    {:reply, {:ok, incident_id}, new_state}
  end
  
  @impl true
  def handle_call({:respond_to_incident, incident_id}, _from, state) do
    case Map.get(state.incidents, incident_id) do
      nil ->
        {:reply, {:error, :incident_not_found}, state}
        
      incident ->
        # Execute response playbook
        {result, new_state} = execute_response(incident, state)
        {:reply, {:ok, result}, new_state}
    end
  end
  
  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    case Map.get(state.incidents, incident_id) do
      nil ->
        {:reply, {:error, :incident_not_found}, state}
        
      incident ->
        # Update incident
        updated_incident = Map.merge(incident, updates)
        |> add_timeline_event("Incident updated", updates)
        
        new_state = put_in(state, [:incidents, incident_id], updated_incident)
        
        {:reply, :ok, new_state}
    end
  end
  
  @impl true
  def handle_call({:collect_forensics, incident_id}, _from, state) do
    case Map.get(state.incidents, incident_id) do
      nil ->
        {:reply, {:error, :incident_not_found}, state}
        
      incident ->
        # Collect forensic data
        forensics = collect_incident_forensics(incident, state)
        
        # Store forensics
        :ets.insert(:incident_forensics, {incident_id, forensics})
        
        # Update incident with forensics reference
        updated_incident = Map.put(incident, :forensics, forensics)
        new_state = put_in(state, [:incidents, incident_id], updated_incident)
        
        {:reply, {:ok, forensics}, new_state}
    end
  end
  
  @impl true
  def handle_call(:get_metrics, _from, state) do
    {:reply, state.metrics, state}
  end
  
  @impl true
  def handle_info({:auto_respond, incident_id}, state) do
    Logger.info("Auto-responding to high severity incident: #{incident_id}")
    
    case Map.get(state.incidents, incident_id) do
      nil ->
        {:noreply, state}
        
      incident ->
        {_result, new_state} = execute_response(incident, state)
        {:noreply, new_state}
    end
  end
  
  @impl true
  def handle_info(:check_incidents, state) do
    # Check for stale incidents or escalations needed
    new_state = check_incident_escalations(state)
    
    # Schedule next check
    Process.send_after(self(), :check_incidents, 5_000)
    
    {:noreply, new_state}
  end
  
  @impl true
  def handle_info({:playbook_step_complete, incident_id, step_name, result}, state) do
    new_state = update_response_progress(state, incident_id, step_name, result)
    {:noreply, new_state}
  end
  
  # Private Functions
  
  defp load_playbooks do
    %{
      # DDoS Response Playbook
      ddos: %{
        name: "DDoS Mitigation",
        type: :ddos,
        severity_threshold: :medium,
        steps: [
          %{
            name: "enable_rate_limiting",
            action: &enable_ddos_protection/1,
            timeout: 5_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "scale_resources",
            action: &auto_scale_resources/1,
            timeout: 30_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "block_sources",
            action: &block_attack_sources/1,
            timeout: 10_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "notify_upstream",
            action: &notify_upstream_provider/1,
            timeout: 5_000,
            on_failure: :continue,
            requires_approval: false
          }
        ],
        rollback_steps: [
          %{
            name: "remove_blocks",
            action: &remove_ip_blocks/1,
            timeout: 10_000,
            on_failure: :continue,
            requires_approval: true
          },
          %{
            name: "scale_down",
            action: &scale_down_resources/1,
            timeout: 30_000,
            on_failure: :continue,
            requires_approval: false
          }
        ]
      },
      
      # Data Breach Response Playbook
      data_breach: %{
        name: "Data Breach Response",
        type: :data_breach,
        severity_threshold: :high,
        steps: [
          %{
            name: "isolate_affected",
            action: &isolate_affected_systems/1,
            timeout: 10_000,
            on_failure: :abort,
            requires_approval: false
          },
          %{
            name: "revoke_credentials",
            action: &revoke_all_credentials/1,
            timeout: 15_000,
            on_failure: :abort,
            requires_approval: false
          },
          %{
            name: "enable_monitoring",
            action: &enable_enhanced_monitoring/1,
            timeout: 5_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "collect_evidence",
            action: &collect_breach_evidence/1,
            timeout: 60_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "notify_legal",
            action: &notify_legal_team/1,
            timeout: 5_000,
            on_failure: :continue,
            requires_approval: true
          }
        ],
        rollback_steps: []
      },
      
      # Malware Response Playbook
      malware: %{
        name: "Malware Containment",
        type: :malware,
        severity_threshold: :medium,
        steps: [
          %{
            name: "quarantine_files",
            action: &quarantine_malicious_files/1,
            timeout: 20_000,
            on_failure: :abort,
            requires_approval: false
          },
          %{
            name: "kill_processes",
            action: &terminate_malicious_processes/1,
            timeout: 10_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "block_c2",
            action: &block_command_control/1,
            timeout: 5_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "scan_network",
            action: &scan_for_lateral_movement/1,
            timeout: 300_000,
            on_failure: :continue,
            requires_approval: false
          }
        ],
        rollback_steps: [
          %{
            name: "restore_files",
            action: &restore_quarantined_files/1,
            timeout: 30_000,
            on_failure: :continue,
            requires_approval: true
          }
        ]
      },
      
      # Insider Threat Response Playbook
      insider_threat: %{
        name: "Insider Threat Response",
        type: :insider_threat,
        severity_threshold: :high,
        steps: [
          %{
            name: "suspend_access",
            action: &suspend_user_access/1,
            timeout: 5_000,
            on_failure: :abort,
            requires_approval: false
          },
          %{
            name: "preserve_evidence",
            action: &preserve_user_activity/1,
            timeout: 60_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "audit_access",
            action: &audit_user_file_access/1,
            timeout: 120_000,
            on_failure: :continue,
            requires_approval: false
          },
          %{
            name: "notify_hr",
            action: &notify_human_resources/1,
            timeout: 5_000,
            on_failure: :continue,
            requires_approval: true
          }
        ],
        rollback_steps: [
          %{
            name: "restore_access",
            action: &restore_user_access/1,
            timeout: 10_000,
            on_failure: :continue,
            requires_approval: true
          }
        ]
      }
    }
  end
  
  defp initialize_collectors do
    %{
      system: &collect_system_state/1,
      network: &collect_network_state/1,
      memory: &collect_memory_dump/1,
      logs: &collect_relevant_logs/1,
      configs: &collect_configurations/1
    }
  end
  
  defp initialize_recovery_procedures do
    %{
      restore_from_backup: &restore_from_backup/1,
      rebuild_system: &rebuild_affected_system/1,
      reset_credentials: &reset_all_credentials/1,
      patch_vulnerabilities: &apply_security_patches/1,
      update_configurations: &harden_configurations/1
    }
  end
  
  defp generate_incident_id do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    random = :crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)
    "INC-#{timestamp}-#{random}"
  end
  
  defp create_incident(id, data, state) do
    # Analyze threat intelligence
    threat_analysis = case ThreatIntelligence.analyze_threat(data) do
      {:ok, analysis} -> analysis
      _ -> %{risk_score: 0.5, indicators: []}
    end
    
    # Determine incident type and severity
    type = classify_incident_type(data, threat_analysis)
    severity = determine_severity(data, threat_analysis)
    
    # Select appropriate playbook
    playbook = select_playbook(type, severity, state.playbooks)
    
    %{
      id: id,
      type: type,
      severity: severity,
      status: :detected,
      zone: data[:zone] || :zombie,
      affected_systems: data[:affected_systems] || [],
      indicators: threat_analysis.indicators ++ (data[:indicators] || []),
      timeline: [
        %{
          timestamp: DateTime.utc_now(),
          event: "Incident detected",
          details: data
        }
      ],
      responders: [],
      playbook: playbook,
      forensics: %{},
      created_at: DateTime.utc_now(),
      updated_at: DateTime.utc_now()
    }
  end
  
  defp classify_incident_type(data, threat_analysis) do
    cond do
      data[:type] -> data.type
      threat_analysis[:predicted_impact] == :service_disruption -> :ddos
      threat_analysis[:predicted_impact] == :data_breach -> :data_breach
      String.contains?(inspect(data), "malware") -> :malware
      data[:source] && data.source[:internal] -> :insider_threat
      true -> :unknown
    end
  end
  
  defp determine_severity(data, threat_analysis) do
    # Use provided severity or calculate based on risk
    severity = data[:severity]
    
    if severity do
      severity
    else
      cond do
        threat_analysis.risk_score > 0.8 -> :critical
        threat_analysis.risk_score > 0.6 -> :high
        threat_analysis.risk_score > 0.4 -> :medium
        true -> :low
      end
    end
  end
  
  defp select_playbook(type, severity, playbooks) do
    playbook = Map.get(playbooks, type)
    
    if playbook && severity_meets_threshold?(severity, playbook.severity_threshold) do
      playbook.name
    else
      "manual_response"
    end
  end
  
  defp severity_meets_threshold?(severity, threshold) do
    severity_levels = [:low, :medium, :high, :critical]
    
    severity_index = Enum.find_index(severity_levels, &(&1 == severity))
    threshold_index = Enum.find_index(severity_levels, &(&1 == threshold))
    
    severity_index >= threshold_index
  end
  
  defp execute_response(incident, state) do
    start_time = System.monotonic_time(:millisecond)
    
    # Update incident status
    incident = update_incident_status(incident, :investigating)
    
    # Get playbook
    playbook = get_playbook_for_incident(incident, state.playbooks)
    
    if playbook do
      # Execute playbook steps
      {success, actions_taken} = execute_playbook(incident, playbook, state)
      
      # Calculate recovery ETA
      recovery_eta = calculate_recovery_eta(incident, success)
      
      # Determine post-incident tasks
      post_tasks = determine_post_incident_tasks(incident, success)
      
      # Update metrics
      elapsed = System.monotonic_time(:millisecond) - start_time
      new_state = update_response_metrics(state, success, elapsed)
      
      result = %{
        success: success,
        incident_id: incident.id,
        actions_taken: actions_taken,
        recovery_eta: recovery_eta,
        post_incident_tasks: post_tasks
      }
      
      {result, new_state}
    else
      # Manual response required
      result = %{
        success: false,
        incident_id: incident.id,
        actions_taken: ["Manual intervention required"],
        recovery_eta: nil,
        post_incident_tasks: ["Assign incident responder", "Create custom playbook"]
      }
      
      {result, state}
    end
  end
  
  defp get_playbook_for_incident(incident, playbooks) do
    Enum.find_value(playbooks, fn {_type, playbook} ->
      if playbook.name == incident.playbook do
        playbook
      end
    end)
  end
  
  defp execute_playbook(incident, playbook, state) do
    # Execute each step in sequence
    {completed_steps, failed_step} = 
      Enum.reduce_while(playbook.steps, {[], nil}, fn step, {completed, _} ->
        case execute_playbook_step(step, incident, state) do
          {:ok, result} ->
            {:cont, {[{step.name, result} | completed], nil}}
            
          {:error, reason} ->
            case step.on_failure do
              :continue ->
                {:cont, {[{step.name, {:failed, reason}} | completed], nil}}
                
              :abort ->
                {:halt, {completed, {step.name, reason}}}
                
              :rollback ->
                # Execute rollback steps
                rollback_result = execute_rollback(playbook, incident, state)
                {:halt, {completed, {:rollback, step.name, rollback_result}}}
            end
        end
      end)
    
    actions_taken = Enum.map(Enum.reverse(completed_steps), fn {name, _result} ->
      humanize_step_name(name)
    end)
    
    {failed_step == nil, actions_taken}
  end
  
  defp execute_playbook_step(step, incident, _state) do
    try do
      # Check if approval needed
      if step.requires_approval do
        Logger.info("Step #{step.name} requires approval - simulating approval")
      end
      
      # Execute the action
      result = case step.action do
        fun when is_function(fun, 1) ->
          fun.(incident)
          
        {module, function, args} ->
          apply(module, function, [incident | args])
      end
      
      # Log step completion
      Logger.info("Executed step #{step.name} for incident #{incident.id}")
      
      {:ok, result}
    catch
      kind, reason ->
        Logger.error("Step #{step.name} failed: #{inspect({kind, reason})}")
        {:error, {kind, reason}}
    end
  end
  
  defp execute_rollback(playbook, incident, state) do
    Enum.map(playbook.rollback_steps, fn step ->
      case execute_playbook_step(step, incident, state) do
        {:ok, _} -> {:ok, step.name}
        {:error, reason} -> {:error, step.name, reason}
      end
    end)
  end
  
  # Playbook Action Functions
  
  defp enable_ddos_protection(incident) do
    Logger.info("Enabling DDoS protection for incident #{incident.id}")
    # Would implement actual DDoS protection
    :ok
  end
  
  defp auto_scale_resources(incident) do
    Logger.info("Auto-scaling resources for incident #{incident.id}")
    # Would implement auto-scaling
    :ok
  end
  
  defp block_attack_sources(incident) do
    Logger.info("Blocking attack sources for incident #{incident.id}")
    # Would implement IP blocking
    attack_ips = Enum.filter(incident.indicators, &(&1.type == :ip))
    Logger.info("Blocked #{length(attack_ips)} IPs")
    :ok
  end
  
  defp notify_upstream_provider(incident) do
    Logger.info("Notifying upstream provider about incident #{incident.id}")
    # Would send notification
    :ok
  end
  
  defp isolate_affected_systems(incident) do
    Logger.info("Isolating affected systems for incident #{incident.id}")
    # Would implement network isolation
    Enum.each(incident.affected_systems, fn system ->
      Logger.info("Isolated system: #{system}")
    end)
    :ok
  end
  
  defp revoke_all_credentials(incident) do
    Logger.info("Revoking credentials for incident #{incident.id}")
    # Would revoke credentials
    :ok
  end
  
  defp enable_enhanced_monitoring(incident) do
    Logger.info("Enabling enhanced monitoring for incident #{incident.id}")
    # Would increase monitoring levels
    :ok
  end
  
  defp collect_breach_evidence(incident) do
    Logger.info("Collecting breach evidence for incident #{incident.id}")
    # Would collect forensic evidence
    %{
      access_logs: "collected",
      data_transfers: "analyzed",
      user_activities: "recorded"
    }
  end
  
  defp notify_legal_team(incident) do
    Logger.info("Notifying legal team about incident #{incident.id}")
    # Would send legal notification
    :ok
  end
  
  defp quarantine_malicious_files(incident) do
    Logger.info("Quarantining malicious files for incident #{incident.id}")
    # Would quarantine files
    malware_hashes = Enum.filter(incident.indicators, &(&1.type == :hash))
    Logger.info("Quarantined #{length(malware_hashes)} files")
    :ok
  end
  
  defp terminate_malicious_processes(incident) do
    Logger.info("Terminating malicious processes for incident #{incident.id}")
    # Would kill processes
    :ok
  end
  
  defp block_command_control(incident) do
    Logger.info("Blocking C2 communications for incident #{incident.id}")
    # Would block C2 domains/IPs
    :ok
  end
  
  defp scan_for_lateral_movement(incident) do
    Logger.info("Scanning for lateral movement from incident #{incident.id}")
    # Would scan network
    %{
      scanned_hosts: 50,
      infected_hosts: 2,
      cleaned_hosts: 2
    }
  end
  
  defp suspend_user_access(incident) do
    Logger.info("Suspending user access for incident #{incident.id}")
    # Would suspend accounts
    :ok
  end
  
  defp preserve_user_activity(incident) do
    Logger.info("Preserving user activity for incident #{incident.id}")
    # Would preserve evidence
    %{
      preserved_logs: true,
      preserved_files: true,
      preserved_emails: true
    }
  end
  
  defp audit_user_file_access(incident) do
    Logger.info("Auditing file access for incident #{incident.id}")
    # Would audit access
    %{
      files_accessed: 150,
      sensitive_files: 5,
      data_exfiltrated: false
    }
  end
  
  defp notify_human_resources(incident) do
    Logger.info("Notifying HR about incident #{incident.id}")
    # Would notify HR
    :ok
  end
  
  defp remove_ip_blocks(_incident) do
    Logger.info("Removing temporary IP blocks")
    :ok
  end
  
  defp scale_down_resources(_incident) do
    Logger.info("Scaling down resources to normal levels")
    :ok
  end
  
  defp restore_quarantined_files(_incident) do
    Logger.info("Restoring quarantined files after verification")
    :ok
  end
  
  defp restore_user_access(_incident) do
    Logger.info("Restoring user access after investigation")
    :ok
  end
  
  # Forensics Collection Functions
  
  defp collect_incident_forensics(incident, state) do
    Enum.reduce(state.forensic_collectors, %{}, fn {type, collector}, acc ->
      try do
        data = collector.(incident)
        Map.put(acc, type, data)
      catch
        _, _ ->
          Map.put(acc, type, %{error: "Collection failed"})
      end
    end)
  end
  
  defp collect_system_state(incident) do
    %{
      timestamp: DateTime.utc_now(),
      affected_systems: incident.affected_systems,
      running_processes: "snapshot_taken",
      open_connections: "captured",
      system_logs: "preserved"
    }
  end
  
  defp collect_network_state(incident) do
    %{
      timestamp: DateTime.utc_now(),
      zone: incident.zone,
      active_connections: "captured",
      routing_table: "saved",
      firewall_rules: "exported"
    }
  end
  
  defp collect_memory_dump(incident) do
    %{
      timestamp: DateTime.utc_now(),
      systems_dumped: length(incident.affected_systems),
      dump_location: "/forensics/#{incident.id}/memory",
      size_gb: :rand.uniform(16)
    }
  end
  
  defp collect_relevant_logs(incident) do
    %{
      timestamp: DateTime.utc_now(),
      log_sources: ["system", "application", "security", "network"],
      time_range: "#{incident.created_at} to now",
      compressed_size_mb: :rand.uniform(500)
    }
  end
  
  defp collect_configurations(incident) do
    %{
      timestamp: DateTime.utc_now(),
      configs_backed_up: true,
      security_settings: "exported",
      access_controls: "documented"
    }
  end
  
  # Recovery Functions
  
  defp restore_from_backup(_incident) do
    Logger.info("Restoring from backup")
    :ok
  end
  
  defp rebuild_affected_system(_incident) do
    Logger.info("Rebuilding affected system")
    :ok
  end
  
  defp reset_all_credentials(_incident) do
    Logger.info("Resetting all credentials")
    :ok
  end
  
  defp apply_security_patches(_incident) do
    Logger.info("Applying security patches")
    :ok
  end
  
  defp harden_configurations(_incident) do
    Logger.info("Hardening system configurations")
    :ok
  end
  
  # Helper Functions
  
  defp update_incident_status(incident, new_status) do
    incident
    |> Map.put(:status, new_status)
    |> Map.put(:updated_at, DateTime.utc_now())
    |> add_timeline_event("Status changed to #{new_status}", %{})
  end
  
  defp add_timeline_event(incident, event, details) do
    new_event = %{
      timestamp: DateTime.utc_now(),
      event: event,
      details: details
    }
    
    Map.update(incident, :timeline, [new_event], &[new_event | &1])
  end
  
  defp calculate_recovery_eta(incident, success) do
    if success do
      base_hours = case incident.severity do
        :critical -> 24
        :high -> 12
        :medium -> 6
        :low -> 2
      end
      
      DateTime.utc_now() |> DateTime.add(base_hours * 3600, :second)
    else
      nil
    end
  end
  
  defp determine_post_incident_tasks(incident, success) do
    base_tasks = [
      "Complete incident report",
      "Update security policies",
      "Conduct lessons learned session"
    ]
    
    severity_tasks = case incident.severity do
      :critical -> ["Executive briefing", "Regulatory notification"]
      :high -> ["Management review", "Security audit"]
      _ -> []
    end
    
    failure_tasks = if success do
      []
    else
      ["Root cause analysis", "Develop custom playbook", "Third-party consultation"]
    end
    
    base_tasks ++ severity_tasks ++ failure_tasks
  end
  
  defp humanize_step_name(name) do
    name
    |> Atom.to_string()
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end
  
  defp update_incident_metrics(state, incident) do
    state
    |> update_in([:metrics, :total_incidents], &(&1 + 1))
    |> update_in([:metrics, :incidents_by_type, incident.type], &((&1 || 0) + 1))
    |> update_in([:metrics, :incidents_by_severity, incident.severity], &((&1 || 0) + 1))
  end
  
  defp update_response_metrics(state, success, elapsed_time) do
    metrics_update = if success do
      [:metrics, :successful_responses]
    else
      [:metrics, :failed_responses]
    end
    
    state
    |> update_in(metrics_update, &(&1 + 1))
    |> update_avg_response_time(elapsed_time)
  end
  
  defp update_avg_response_time(state, new_time) do
    total = state.metrics.successful_responses + state.metrics.failed_responses
    current_avg = state.metrics.avg_response_time
    
    new_avg = ((current_avg * (total - 1)) + new_time) / total
    
    put_in(state, [:metrics, :avg_response_time], new_avg)
  end
  
  defp check_incident_escalations(state) do
    now = DateTime.utc_now()
    
    Enum.reduce(state.incidents, state, fn {id, incident}, acc ->
      # Check if incident needs escalation
      time_in_status = DateTime.diff(now, incident.updated_at, :second)
      
      needs_escalation = case incident.status do
        :detected when time_in_status > 300 -> true  # 5 minutes
        :investigating when time_in_status > 1800 -> true  # 30 minutes
        :containing when time_in_status > 3600 -> true  # 1 hour
        _ -> false
      end
      
      if needs_escalation do
        Logger.warning("Incident #{id} needs escalation - stuck in #{incident.status}")
        # Would trigger escalation
      end
      
      acc
    end)
  end
  
  defp update_response_progress(state, incident_id, step_name, result) do
    case get_in(state, [:incidents, incident_id]) do
      nil -> state
      incident ->
        updated_incident = add_timeline_event(
          incident,
          "Completed step: #{step_name}",
          %{result: result}
        )
        
        put_in(state, [:incidents, incident_id], updated_incident)
    end
  end
end