defmodule VSM.Security.ZombieDetection.BotnetDetectionTest do
  @moduledoc """
  Comprehensive tests for zombie/botnet detection using neural networks
  and behavioral analysis in the Z3N framework.
  """
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  
  alias VSM.Security.Z3N.Neural.ZombieDetector
  alias VSM.Security.Z3N.Network.BehaviorAnalyzer
  alias VSM.Security.BloomFilters.ProbabilisticFilter
  
  setup do
    # Initialize detection systems
    {:ok, zombie_detector} = ZombieDetector.start_link(
      name: :test_zombie_detector,
      model_path: "priv/models/zombie_detector.axon"
    )
    
    {:ok, behavior_analyzer} = BehaviorAnalyzer.start_link(
      name: :test_behavior_analyzer
    )
    
    {:ok, bloom_filter} = ProbabilisticFilter.start_link(
      name: :test_bloom_filter,
      size: 100_000,
      hash_functions: 3
    )
    
    on_exit(fn ->
      GenServer.stop(zombie_detector)
      GenServer.stop(behavior_analyzer)
      GenServer.stop(bloom_filter)
    end)
    
    %{
      zombie_detector: zombie_detector,
      behavior_analyzer: behavior_analyzer,
      bloom_filter: bloom_filter
    }
  end
  
  describe "Botnet Pattern Detection" do
    test "command and control communication detection", %{zombie_detector: zombie_detector} do
      # Simulate C&C patterns
      c2_patterns = [
        %{
          source_ip: "192.168.1.100",
          dest_ip: "10.0.0.1",
          pattern: :periodic_beacon,
          interval_ms: 60_000,
          payload_size: 128,
          encryption: :xor
        },
        %{
          source_ip: "192.168.1.101",
          dest_ip: "10.0.0.1",
          pattern: :burst_communication,
          packets: 1000,
          duration_ms: 100
        },
        %{
          source_ip: "192.168.1.102",
          dest_ip: "evil.domain.com",
          pattern: :dns_tunneling,
          queries_per_minute: 120,
          subdomain_length: 63
        }
      ]
      
      detection_results = Enum.map(c2_patterns, fn pattern ->
        ZombieDetector.analyze_traffic(zombie_detector, pattern)
      end)
      
      # All C&C patterns should be detected
      assert Enum.all?(detection_results, &match?({:malicious, :c2_communication, _}, &1))
      
      # Verify neural network confidence
      confidences = Enum.map(detection_results, fn {:malicious, _, conf} -> conf end)
      assert Enum.all?(confidences, &(&1 > 0.8))
    end
    
    test "DDoS participation detection", %{behavior_analyzer: behavior_analyzer} do
      # Simulate DDoS attack patterns
      ddos_behaviors = [
        # SYN flood pattern
        %{
          type: :syn_flood,
          target: "victim.com",
          packets_per_second: 10_000,
          source_ports: Enum.map(1..1000, fn _ -> :rand.uniform(65535) end),
          flags: [:syn]
        },
        # UDP flood pattern
        %{
          type: :udp_flood,
          target: "victim.com",
          bandwidth_mbps: 100,
          packet_sizes: [64, 128, 256, 512, 1024],
          randomized_payload: true
        },
        # HTTP flood pattern
        %{
          type: :http_flood,
          target: "victim.com",
          requests_per_second: 1000,
          user_agents: ["Bot/1.0", "Bot/2.0"],
          paths: ["/", "/api", "/login"]
        }
      ]
      
      results = Enum.map(ddos_behaviors, fn behavior ->
        BehaviorAnalyzer.detect_ddos_participation(behavior_analyzer, behavior)
      end)
      
      assert Enum.all?(results, &match?({:ddos_detected, _}, &1))
      
      # Check mitigation triggered
      assert_received {:mitigation_activated, :rate_limiting}
    end
    
    test "lateral movement detection", %{zombie_detector: zombie_detector} do
      # Simulate lateral movement in network
      movement_sequence = [
        %{time: 0, source: "192.168.1.10", target: "192.168.1.20", method: :ssh_brute},
        %{time: 60, source: "192.168.1.20", target: "192.168.1.30", method: :smb_exploit},
        %{time: 120, source: "192.168.1.30", target: "192.168.1.40", method: :rdp_attack},
        %{time: 180, source: "192.168.1.40", target: "192.168.1.50", method: :psexec}
      ]
      
      analysis = ZombieDetector.analyze_movement_pattern(
        zombie_detector,
        movement_sequence
      )
      
      assert {:lateral_movement_detected, details} = analysis
      assert details.confidence > 0.9
      assert details.infection_chain == ["192.168.1.10", "192.168.1.20", 
                                        "192.168.1.30", "192.168.1.40", 
                                        "192.168.1.50"]
    end
    
    test "cryptomining behavior detection", %{behavior_analyzer: behavior_analyzer} do
      # Simulate cryptomining patterns
      mining_indicators = %{
        cpu_usage: 95.5,
        gpu_usage: 98.2,
        memory_pattern: :steady_high,
        network_connections: [
          %{host: "pool.mining.com", port: 3333, protocol: :stratum},
          %{host: "backup.pool.com", port: 3334, protocol: :stratum}
        ],
        process_name: "svchost.exe",  # Disguised process
        power_consumption: :abnormal_high
      }
      
      result = BehaviorAnalyzer.detect_cryptomining(behavior_analyzer, mining_indicators)
      
      assert {:cryptominer_detected, details} = result
      assert details.type in [:monero, :ethereum, :bitcoin]
      assert details.certainty > 0.85
    end
  end
  
  describe "Behavioral Anomaly Detection" do
    test "sudden behavior change detection", %{behavior_analyzer: behavior_analyzer} do
      # Establish baseline behavior
      baseline_period = for hour <- 0..23 do
        %{
          hour: hour,
          connections: 10 + :rand.uniform(5),
          bandwidth_kb: 100 + :rand.uniform(50),
          processes: 20 + :rand.uniform(5),
          dns_queries: 5 + :rand.uniform(3)
        }
      end
      
      :ok = BehaviorAnalyzer.train_baseline(behavior_analyzer, baseline_period)
      
      # Inject anomalous behavior
      anomalous_behavior = %{
        hour: 2,  # 2 AM
        connections: 500,  # Massive spike
        bandwidth_kb: 10_000,  # Huge bandwidth
        processes: 100,  # Many new processes
        dns_queries: 1000  # DNS abuse
      }
      
      result = BehaviorAnalyzer.detect_anomaly(behavior_analyzer, anomalous_behavior)
      
      assert {:anomaly_detected, metrics} = result
      assert metrics.deviation_score > 10.0
      assert :zombie_activation in metrics.possible_causes
    end
    
    test "sleep pattern detection for dormant bots", %{zombie_detector: zombie_detector} do
      # Simulate dormant bot waking pattern
      activity_log = [
        # Long dormant period
        %{timestamp: ~U[2024-01-01 00:00:00Z], activity: :none},
        %{timestamp: ~U[2024-01-15 00:00:00Z], activity: :none},
        %{timestamp: ~U[2024-01-30 00:00:00Z], activity: :none},
        # Sudden activation
        %{timestamp: ~U[2024-02-01 03:00:00Z], activity: :beacon},
        %{timestamp: ~U[2024-02-01 03:01:00Z], activity: :download_payload},
        %{timestamp: ~U[2024-02-01 03:02:00Z], activity: :execute_command},
        %{timestamp: ~U[2024-02-01 03:03:00Z], activity: :spread_lateral}
      ]
      
      analysis = ZombieDetector.analyze_sleep_pattern(zombie_detector, activity_log)
      
      assert {:dormant_bot_activated, details} = analysis
      assert details.dormant_days == 31
      assert details.activation_trigger in [:time_based, :command_triggered]
    end
    
    test "communication pattern clustering", %{zombie_detector: zombie_detector} do
      # Generate mixed traffic patterns
      traffic_samples = [
        # Normal traffic
        %{src: "192.168.1.10", dst: "google.com", bytes: 1024, pattern: :https},
        %{src: "192.168.1.11", dst: "github.com", bytes: 2048, pattern: :git},
        # Botnet traffic
        %{src: "192.168.1.50", dst: "10.0.0.1", bytes: 128, pattern: :periodic},
        %{src: "192.168.1.51", dst: "10.0.0.1", bytes: 128, pattern: :periodic},
        %{src: "192.168.1.52", dst: "10.0.0.1", bytes: 128, pattern: :periodic}
      ]
      
      clusters = ZombieDetector.cluster_traffic_patterns(zombie_detector, traffic_samples)
      
      assert {:ok, cluster_map} = clusters
      assert map_size(cluster_map) >= 2  # At least normal and botnet clusters
      
      # Verify botnet cluster identified
      botnet_cluster = Enum.find(cluster_map, fn {_id, cluster} ->
        cluster.pattern_type == :botnet
      end)
      
      assert botnet_cluster != nil
      {_, botnet_data} = botnet_cluster
      assert length(botnet_data.members) >= 3
    end
  end
  
  describe "Neural Network Detection Tests" do
    test "adversarial robustness against evasion", %{zombie_detector: zombie_detector} do
      # Create evasion attempts
      evasion_techniques = [
        # Traffic padding
        %{
          technique: :padding,
          original_payload: <<1, 2, 3, 4>>,
          padded_payload: <<1, 2, 3, 4, 0, 0, 0, 0, 0, 0>>
        },
        # Encryption obfuscation
        %{
          technique: :encryption,
          traffic: :encrypted_c2,
          algorithm: :custom_xor,
          key_rotation: true
        },
        # Timing manipulation
        %{
          technique: :timing_jitter,
          base_interval: 60_000,
          jitter_range: 30_000,
          distribution: :gaussian
        },
        # Protocol mimicry
        %{
          technique: :protocol_mimicry,
          mimics: :https,
          actual: :c2_beacon,
          headers: %{"User-Agent" => "Mozilla/5.0"}
        }
      ]
      
      detection_results = Enum.map(evasion_techniques, fn technique ->
        ZombieDetector.detect_despite_evasion(zombie_detector, technique)
      end)
      
      # Should still detect most evasion attempts
      successful_detections = Enum.count(detection_results, &match?({:detected, _}, &1))
      assert successful_detections >= 3  # At least 75% detection rate
    end
    
    test "ensemble model voting for accuracy", %{zombie_detector: zombie_detector} do
      # Test ensemble of different models
      suspicious_activity = %{
        network_features: [0.8, 0.2, 0.9, 0.1, 0.7],
        behavioral_features: [0.9, 0.9, 0.1, 0.2, 0.8],
        temporal_features: [0.7, 0.8, 0.9, 0.6, 0.5]
      }
      
      # Get predictions from ensemble
      ensemble_result = ZombieDetector.ensemble_predict(
        zombie_detector,
        suspicious_activity
      )
      
      assert {:prediction, prediction_data} = ensemble_result
      assert prediction_data.consensus in [:malicious, :benign]
      assert length(prediction_data.model_votes) >= 3
      assert prediction_data.confidence >= 0.0 and prediction_data.confidence <= 1.0
      
      # Verify voting mechanism
      vote_distribution = Enum.frequencies(prediction_data.model_votes)
      winning_vote = Enum.max_by(vote_distribution, fn {_k, v} -> v end)
      {winner, _count} = winning_vote
      assert winner == prediction_data.consensus
    end
    
    test "online learning from new threats", %{zombie_detector: zombie_detector} do
      # Simulate new threat discovery
      new_threat_samples = [
        %{
          features: [0.95, 0.1, 0.85, 0.05, 0.9],
          label: :new_botnet_variant,
          confidence: 0.95
        },
        %{
          features: [0.9, 0.15, 0.8, 0.1, 0.85],
          label: :new_botnet_variant,
          confidence: 0.92
        }
      ]
      
      # Test online learning
      learning_result = ZombieDetector.online_learn(
        zombie_detector,
        new_threat_samples
      )
      
      assert {:model_updated, metrics} = learning_result
      assert metrics.samples_learned == 2
      assert metrics.model_version > metrics.previous_version
      
      # Verify improved detection
      similar_threat = %{
        features: [0.92, 0.12, 0.83, 0.08, 0.87]
      }
      
      prediction = ZombieDetector.predict(zombie_detector, similar_threat)
      assert {:malicious, :new_botnet_variant, confidence} = prediction
      assert confidence > 0.8
    end
  end
  
  describe "Bloom Filter Integration Tests" do
    test "known botnet IP filtering", %{bloom_filter: bloom_filter} do
      # Load known botnet IPs
      botnet_ips = [
        "10.0.0.1",
        "10.0.0.2",
        "192.168.100.50",
        "172.16.0.100",
        "evil.botnet.com"
      ]
      
      Enum.each(botnet_ips, fn ip ->
        :ok = ProbabilisticFilter.add(bloom_filter, ip)
      end)
      
      # Test detection
      test_ips = botnet_ips ++ ["8.8.8.8", "1.1.1.1", "google.com"]
      
      results = Enum.map(test_ips, fn ip ->
        {ip, ProbabilisticFilter.contains?(bloom_filter, ip)}
      end)
      
      # All botnet IPs should be detected
      botnet_results = Enum.filter(results, fn {ip, _} -> ip in botnet_ips end)
      assert Enum.all?(botnet_results, fn {_, contained} -> contained end)
      
      # Check false positive rate
      legitimate_results = Enum.filter(results, fn {ip, _} -> ip not in botnet_ips end)
      false_positives = Enum.count(legitimate_results, fn {_, contained} -> contained end)
      assert false_positives <= 1  # Allow max 1 false positive
    end
    
    test "dynamic filter updates", %{bloom_filter: bloom_filter} do
      # Simulate real-time threat feed
      threat_feed = Stream.repeatedly(fn ->
        "10.#{:rand.uniform(255)}.#{:rand.uniform(255)}.#{:rand.uniform(255)}"
      end)
      |> Stream.take(1000)
      
      # Add threats in batches
      threat_feed
      |> Stream.chunk_every(100)
      |> Enum.each(fn batch ->
        Enum.each(batch, &ProbabilisticFilter.add(bloom_filter, &1))
      end)
      
      # Verify filter statistics
      stats = ProbabilisticFilter.get_stats(bloom_filter)
      
      assert stats.estimated_elements >= 900  # Some duplicates expected
      assert stats.false_positive_rate < 0.01
      assert stats.fill_ratio < 0.5  # Not overfilled
    end
  end
  
  describe "Stress Testing and Scalability" do
    test "high-volume traffic analysis", %{zombie_detector: zombie_detector} do
      # Generate high-volume traffic
      traffic_volume = 10_000
      
      traffic_stream = Stream.repeatedly(fn ->
        %{
          src_ip: "192.168.#{:rand.uniform(255)}.#{:rand.uniform(255)}",
          dst_ip: "10.0.#{:rand.uniform(255)}.#{:rand.uniform(255)}",
          bytes: :rand.uniform(10_000),
          timestamp: System.system_time(:millisecond)
        }
      end)
      |> Stream.take(traffic_volume)
      
      # Process with timing
      start_time = System.monotonic_time(:millisecond)
      
      results = traffic_stream
      |> Stream.chunk_every(100)
      |> Stream.map(fn batch ->
        ZombieDetector.batch_analyze(zombie_detector, batch)
      end)
      |> Enum.to_list()
      
      end_time = System.monotonic_time(:millisecond)
      processing_time = end_time - start_time
      
      # Performance assertions
      assert length(results) == 100  # All batches processed
      assert processing_time < 5000  # Under 5 seconds for 10k items
      
      # Calculate throughput
      throughput = traffic_volume / (processing_time / 1000)
      assert throughput > 1000  # At least 1000 items/second
    end
    
    test "concurrent detection under load", %{
      zombie_detector: zombie_detector,
      behavior_analyzer: behavior_analyzer
    } do
      # Spawn concurrent detection tasks
      task_count = 100
      
      tasks = for i <- 1..task_count do
        Task.async(fn ->
          sample = %{
            id: i,
            src_ip: "192.168.1.#{rem(i, 255)}",
            behavior: if(rem(i, 10) == 0, do: :suspicious, else: :normal)
          }
          
          zombie_result = ZombieDetector.analyze(zombie_detector, sample)
          behavior_result = BehaviorAnalyzer.analyze(behavior_analyzer, sample)
          
          {zombie_result, behavior_result}
        end)
      end
      
      # Await all results with timeout
      results = Task.await_many(tasks, 10_000)
      
      # All tasks should complete
      assert length(results) == task_count
      
      # No errors expected
      assert Enum.all?(results, fn {z_result, b_result} ->
        match?({:ok, _}, z_result) or match?({:malicious, _, _}, z_result)
      end)
    end
    
    test "memory stability under sustained load", %{zombie_detector: zombie_detector} do
      # Get initial memory
      initial_memory = :erlang.memory(:total)
      
      # Run sustained load for 10 seconds
      end_time = System.monotonic_time(:second) + 10
      
      memory_samples = Stream.repeatedly(fn ->
        # Generate and analyze traffic
        batch = for _ <- 1..100 do
          %{
            data: :crypto.strong_rand_bytes(1024),
            timestamp: System.system_time()
          }
        end
        
        ZombieDetector.batch_analyze(zombie_detector, batch)
        
        # Sample memory
        :erlang.memory(:total)
      end)
      |> Stream.take_while(fn _ -> 
        System.monotonic_time(:second) < end_time 
      end)
      |> Enum.to_list()
      
      # Calculate memory growth
      final_memory = List.last(memory_samples)
      memory_growth = final_memory - initial_memory
      memory_growth_mb = memory_growth / 1_048_576
      
      # Memory should be stable (less than 100MB growth)
      assert memory_growth_mb < 100
      
      # Check for memory leak patterns
      # Memory should stabilize, not continuously grow
      midpoint = div(length(memory_samples), 2)
      first_half_avg = Enum.sum(Enum.take(memory_samples, midpoint)) / midpoint
      second_half_avg = Enum.sum(Enum.drop(memory_samples, midpoint)) / (length(memory_samples) - midpoint)
      
      growth_rate = (second_half_avg - first_half_avg) / first_half_avg
      assert growth_rate < 0.1  # Less than 10% growth between halves
    end
  end
end