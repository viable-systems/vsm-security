defmodule VSM.Security.Integration.FullStackTest do
  @moduledoc """
  Full stack integration tests for the VSM security system.
  Tests the complete security pipeline from ingress to response.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  
  alias VSM.Security.Z3N.{ZoneManager, Neural.NeuralDefender}
  alias VSM.Security.BloomFilters.ProbabilisticFilter
  alias VSM.Security.Auth.{TokenManager, SessionManager}
  
  @tag :integration
  describe "Complete Security Pipeline" do
    setup do
      # Start all security components
      {:ok, _} = Application.ensure_all_started(:vsm_security)
      
      # Additional test-specific components
      {:ok, test_monitor} = GenServer.start_link(SecurityTestMonitor, 
        name: :test_monitor
      )
      
      on_exit(fn ->
        GenServer.stop(test_monitor)
      end)
      
      %{monitor: test_monitor}
    end
    
    test "legitimate user flow with progressive security checks", %{monitor: monitor} do
      # Simulate legitimate user journey
      user_session = %{
        user_id: "user_#{System.unique_integer([:positive])}",
        ip_address: "192.168.1.100",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        device_id: "device_123"
      }
      
      # Step 1: Initial connection
      {:ok, initial_zone} = SecurityPipeline.handle_connection(%{
        source_ip: user_session.ip_address,
        headers: %{"User-Agent" => user_session.user_agent},
        timestamp: System.system_time(:millisecond)
      })
      
      assert initial_zone == "public"
      
      # Step 2: Authentication attempt
      auth_result = SecurityPipeline.authenticate(%{
        username: "testuser",
        password: "SecurePass123!",
        session_data: user_session
      })
      
      assert {:ok, %{token: token, zone: "authenticated"}} = auth_result
      
      # Step 3: Normal activity
      activities = for i <- 1..50 do
        SecurityPipeline.process_request(%{
          token: token,
          action: Enum.random([:read, :write, :list]),
          resource: "resource_#{i}",
          session: user_session
        })
      end
      
      # All normal activities should succeed
      assert Enum.all?(activities, &match?({:ok, _}, &1))
      
      # Verify no security alerts
      alerts = GenServer.call(monitor, :get_alerts)
      assert length(alerts) == 0
    end
    
    test "attack progression with escalating defenses" do
      attacker_ip = "10.0.0.#{:rand.uniform(255)}"
      
      # Phase 1: Reconnaissance
      recon_results = for port <- [22, 80, 443, 3306, 5432] do
        SecurityPipeline.handle_connection(%{
          source_ip: attacker_ip,
          destination_port: port,
          flags: [:syn],
          timestamp: System.system_time(:millisecond)
        })
      end
      
      # Should detect port scanning
      assert Enum.any?(recon_results, &match?({:blocked, :port_scan_detected}, &1))
      
      # Phase 2: Brute force attempt
      brute_force_results = for i <- 1..100 do
        SecurityPipeline.authenticate(%{
          username: "admin",
          password: "password#{i}",
          session_data: %{ip_address: attacker_ip}
        })
      end
      
      # Should block after threshold
      blocked_count = Enum.count(brute_force_results, 
        &match?({:error, :ip_blocked}, &1))
      assert blocked_count > 50
      
      # Phase 3: Verify IP is blacklisted
      future_attempt = SecurityPipeline.handle_connection(%{
        source_ip: attacker_ip,
        timestamp: System.system_time(:millisecond) + 3600_000
      })
      
      assert {:blocked, :blacklisted_ip} = future_attempt
    end
    
    test "coordinated botnet attack simulation" do
      # Generate botnet IPs
      botnet_size = 100
      botnet_ips = for i <- 1..botnet_size do
        "10.#{div(i, 255)}.#{rem(i, 255)}.#{:rand.uniform(255)}"
      end
      
      # Phase 1: Distributed reconnaissance
      recon_tasks = Task.async_stream(botnet_ips, fn ip ->
        SecurityPipeline.handle_connection(%{
          source_ip: ip,
          destination_port: 80,
          timestamp: System.system_time(:millisecond)
        })
      end, max_concurrency: 50)
      
      recon_results = Enum.map(recon_tasks, fn {:ok, result} -> result end)
      
      # Phase 2: Coordinated attack
      attack_start = System.system_time(:millisecond)
      
      attack_tasks = Task.async_stream(
        Stream.cycle(botnet_ips) |> Stream.take(1000),
        fn ip ->
          SecurityPipeline.process_request(%{
            source_ip: ip,
            method: :post,
            path: "/api/heavy-endpoint",
            payload_size: 10_000,
            timestamp: System.system_time(:millisecond)
          })
        end,
        max_concurrency: 100,
        timeout: 5000
      )
      
      attack_results = Enum.map(attack_tasks, fn 
        {:ok, result} -> result
        {:exit, :timeout} -> {:error, :timeout}
      end)
      
      attack_duration = System.system_time(:millisecond) - attack_start
      
      # Analysis
      blocked_percentage = Enum.count(attack_results, 
        &match?({:blocked, _}, &1)) / length(attack_results)
      
      # Should detect and block botnet
      assert blocked_percentage > 0.7  # 70% blocking rate
      assert attack_duration < 10_000  # Defense activated within 10s
      
      # Verify neural detection
      assert_received {:neural_alert, :botnet_detected, %{
        confidence: confidence,
        bot_count: count
      }}
      
      assert confidence > 0.9
      assert count >= botnet_size * 0.8
    end
    
    test "adaptive attack with evasion techniques" do
      sophisticated_attacker = %{
        ip_pool: for(_ <- 1..10, do: random_ip()),
        user_agents: [
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ],
        timing_strategy: :random_delay
      }
      
      # Implement adaptive attack
      attack_phases = [
        # Phase 1: Slow reconnaissance
        fn attacker ->
          for ip <- Enum.take(attacker.ip_pool, 3) do
            :timer.sleep(:rand.uniform(5000))  # Random delay
            
            SecurityPipeline.handle_connection(%{
              source_ip: ip,
              user_agent: Enum.random(attacker.user_agents),
              action: :get,
              path: "/robots.txt"
            })
          end
        end,
        
        # Phase 2: Credential stuffing with rate limiting evasion
        fn attacker ->
          credentials = [
            {"admin", "admin123"},
            {"user", "password"},
            {"root", "toor"}
          ]
          
          for {user, pass} <- credentials,
              ip <- attacker.ip_pool do
            :timer.sleep(1000 + :rand.uniform(2000))
            
            SecurityPipeline.authenticate(%{
              username: user,
              password: pass,
              session_data: %{
                ip_address: ip,
                user_agent: Enum.random(attacker.user_agents)
              }
            })
          end
        end,
        
        # Phase 3: Application-layer DDoS
        fn attacker ->
          Stream.repeatedly(fn ->
            ip = Enum.random(attacker.ip_pool)
            
            SecurityPipeline.process_request(%{
              source_ip: ip,
              method: :post,
              path: "/api/search",
              payload: %{
                query: String.duplicate("A", 10_000),
                filters: for(_ <- 1..100, do: %{field: "test", value: "test"})
              }
            })
          end)
          |> Stream.take(100)
          |> Enum.to_list()
        end
      ]
      
      # Execute attack phases
      phase_results = Enum.map(attack_phases, fn phase ->
        phase.(sophisticated_attacker)
      end)
      
      # Verify adaptive defenses triggered
      assert_received {:defense_escalation, :level_1}
      assert_received {:defense_escalation, :level_2}
      assert_received {:defense_escalation, :level_3}
      
      # Check if attack patterns were learned
      neural_update = GenServer.call(:neural_defender, :get_latest_patterns)
      assert length(neural_update.new_patterns) > 0
      assert neural_update.adaptation_score > 0.8
    end
  end
  
  @tag :integration
  describe "Cross-Component Security Integration" do
    test "bloom filter and neural network cooperation" do
      # Seed bloom filter with known bad IPs
      bad_ips = for i <- 1..1000, do: "10.0.#{div(i, 255)}.#{rem(i, 255)}"
      
      Enum.each(bad_ips, fn ip ->
        VSM.Security.BloomFilters.add_threat(ip)
      end)
      
      # Test hybrid detection
      test_ips = bad_ips ++ for(_ <- 1..1000, do: random_ip())
      
      detection_results = Enum.map(test_ips, fn ip ->
        # Quick bloom filter check
        bloom_result = VSM.Security.BloomFilters.check_threat(ip)
        
        # Neural analysis for uncertain cases
        neural_result = if bloom_result == :maybe_threat do
          VSM.Security.Neural.analyze_ip_behavior(ip)
        end
        
        {ip, bloom_result, neural_result}
      end)
      
      # Analyze detection accuracy
      {known_bad, unknown} = Enum.split(detection_results, 1000)
      
      # Bloom filter should catch most known bad IPs
      bloom_detections = Enum.count(known_bad, fn {_, bloom, _} -> 
        bloom in [:threat, :maybe_threat]
      end)
      assert bloom_detections > 950  # 95% detection
      
      # Neural network should help with uncertain cases
      neural_assists = Enum.count(detection_results, fn {_, bloom, neural} ->
        bloom == :maybe_threat and neural != nil
      end)
      assert neural_assists > 0
    end
    
    test "zone security with progressive trust" do
      # Create user session
      session = %{
        user_id: "test_user_#{System.unique_integer()}",
        ip_address: "192.168.1.50",
        trust_score: 0.5
      }
      
      # Start in public zone
      {:ok, current_zone} = VSM.Security.Zones.assign_zone(session)
      assert current_zone == "public"
      
      # Perform legitimate actions to build trust
      trust_building_actions = [
        {:authenticate, %{method: :mfa, success: true}},
        {:access_resource, %{sensitive: false, success: true}},
        {:complete_transaction, %{value: 100, success: true}},
        {:verify_email, %{success: true}},
        {:enable_2fa, %{success: true}}
      ]
      
      zones_progression = Enum.map(trust_building_actions, fn {action, result} ->
        {:ok, new_session} = VSM.Security.Trust.update_score(session, action, result)
        {:ok, new_zone} = VSM.Security.Zones.assign_zone(new_session)
        
        {action, new_session.trust_score, new_zone}
      end)
      
      # Verify trust progression
      trust_scores = Enum.map(zones_progression, fn {_, score, _} -> score end)
      assert List.first(trust_scores) < List.last(trust_scores)
      
      # Verify zone elevation
      final_zone = elem(List.last(zones_progression), 2)
      assert final_zone in ["trusted", "privileged"]
    end
    
    test "multi-layer defense coordination" do
      attack_scenario = %{
        phase1: %{type: :reconnaissance, intensity: :low},
        phase2: %{type: :exploitation, intensity: :medium},
        phase3: %{type: :lateral_movement, intensity: :high},
        phase4: %{type: :data_exfiltration, intensity: :critical}
      }
      
      defense_responses = Enum.map(attack_scenario, fn {phase, attack} ->
        response = VSM.Security.Coordinator.respond_to_threat(%{
          attack_type: attack.type,
          intensity: attack.intensity,
          timestamp: System.system_time(:millisecond)
        })
        
        {phase, response}
      end)
      
      # Verify escalating defenses
      expected_responses = %{
        phase1: [:logging, :monitoring],
        phase2: [:blocking, :alerting, :rate_limiting],
        phase3: [:isolation, :neural_analysis, :zone_lockdown],
        phase4: [:full_block, :incident_response, :forensics]
      }
      
      Enum.each(defense_responses, fn {phase, response} ->
        expected = Map.get(expected_responses, phase)
        assert Enum.all?(expected, &(&1 in response.actions))
      end)
    end
  end
  
  @tag :integration  
  describe "Security Metrics and Monitoring" do
    test "real-time threat metrics collection" do
      # Generate mixed traffic
      traffic_duration = 5_000  # 5 seconds
      end_time = System.monotonic_time(:millisecond) + traffic_duration
      
      # Spawn traffic generators
      generators = [
        # Normal traffic
        Task.async(fn ->
          generate_traffic(:normal, end_time, 100)
        end),
        
        # Suspicious traffic
        Task.async(fn ->
          generate_traffic(:suspicious, end_time, 20)
        end),
        
        # Malicious traffic
        Task.async(fn ->
          generate_traffic(:malicious, end_time, 10)
        end)
      ]
      
      # Let traffic run
      Task.await_many(generators, traffic_duration + 1000)
      
      # Collect metrics
      metrics = VSM.Security.Metrics.get_summary(:last_5_seconds)
      
      # Verify metrics collected
      assert metrics.total_requests > 0
      assert metrics.blocked_requests > 0
      assert metrics.threat_categories |> Map.keys() |> length() > 0
      
      # Calculate security effectiveness
      block_rate = metrics.blocked_requests / metrics.threat_requests
      assert block_rate > 0.8  # 80% blocking effectiveness
      
      # Verify performance metrics
      assert metrics.avg_latency_ms < 10
      assert metrics.p99_latency_ms < 50
    end
    
    test "security event correlation" do
      # Create related security events
      attacker_ip = "10.0.0.100"
      target_user = "admin"
      
      events = [
        %{type: :failed_login, ip: attacker_ip, user: target_user, time: 0},
        %{type: :failed_login, ip: attacker_ip, user: target_user, time: 1000},
        %{type: :failed_login, ip: attacker_ip, user: target_user, time: 2000},
        %{type: :port_scan, ip: attacker_ip, ports: [22, 3306], time: 3000},
        %{type: :exploit_attempt, ip: attacker_ip, cve: "CVE-2021-1234", time: 4000}
      ]
      
      # Process events
      Enum.each(events, fn event ->
        VSM.Security.EventProcessor.process(event)
      end)
      
      # Check correlation
      :timer.sleep(100)  # Allow correlation engine to process
      
      correlated = VSM.Security.Correlator.get_attack_chains()
      
      assert length(correlated) > 0
      
      [attack_chain | _] = correlated
      assert attack_chain.attacker_ip == attacker_ip
      assert attack_chain.attack_stages == [
        :reconnaissance,
        :credential_attack,
        :exploitation
      ]
      assert attack_chain.risk_score > 8.0  # High risk
    end
  end
  
  # Helper functions
  defp random_ip do
    "#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}"
  end
  
  defp generate_traffic(type, end_time, rate_per_sec) do
    Stream.repeatedly(fn ->
      now = System.monotonic_time(:millisecond)
      if now < end_time do
        request = build_request(type)
        SecurityPipeline.process_request(request)
        
        # Rate limiting
        :timer.sleep(div(1000, rate_per_sec))
        :ok
      else
        :done
      end
    end)
    |> Stream.take_while(&(&1 == :ok))
    |> Stream.run()
  end
  
  defp build_request(:normal) do
    %{
      source_ip: random_ip(),
      method: Enum.random([:get, :post]),
      path: Enum.random(["/", "/api/users", "/api/products"]),
      headers: %{"User-Agent" => "Mozilla/5.0"}
    }
  end
  
  defp build_request(:suspicious) do
    %{
      source_ip: "10.0.0.#{:rand.uniform(255)}",
      method: :post,
      path: "/admin/#{Enum.random(["config", "users", "backup"])}",
      headers: %{"User-Agent" => "scanner/1.0"}
    }
  end
  
  defp build_request(:malicious) do
    %{
      source_ip: "10.0.0.#{:rand.uniform(10)}",
      method: Enum.random([:post, :put, :delete]),
      path: Enum.random([
        "/admin/execute",
        "/.git/config",
        "/wp-admin/admin-ajax.php"
      ]),
      payload: %{
        cmd: "cat /etc/passwd",
        exploit: "' OR '1'='1"
      }
    }
  end
end

# Test helper module for monitoring
defmodule SecurityTestMonitor do
  use GenServer
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, %{alerts: []}, opts)
  end
  
  def init(state) do
    # Subscribe to security events
    :ok = VSM.Security.Events.subscribe(self())
    {:ok, state}
  end
  
  def handle_info({:security_alert, alert}, state) do
    {:noreply, %{state | alerts: [alert | state.alerts]}}
  end
  
  def handle_call(:get_alerts, _from, state) do
    {:reply, state.alerts, state}
  end
end