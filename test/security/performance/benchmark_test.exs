defmodule VSM.Security.Performance.BenchmarkTest do
  @moduledoc """
  Performance benchmarks for security components including
  Bloom filters, neural network inference, and zone routing.
  """
  use ExUnit.Case, async: false
  
  alias VSM.Security.BloomFilters.ProbabilisticFilter
  alias VSM.Security.Z3N.Neural.{NeuralDefender, ZombieDetector}
  alias VSM.Security.Z3N.Zones.ZoneRouter
  
  @tag :benchmark
  describe "Bloom Filter Performance" do
    setup do
      sizes = [1_000, 10_000, 100_000, 1_000_000]
      filters = Enum.map(sizes, fn size ->
        {:ok, filter} = ProbabilisticFilter.start_link(
          size: size,
          hash_functions: 3,
          name: :"filter_#{size}"
        )
        {size, filter}
      end)
      
      on_exit(fn ->
        Enum.each(filters, fn {_size, filter} ->
          GenServer.stop(filter)
        end)
      end)
      
      {:ok, filters: filters}
    end
    
    test "insertion performance scaling", %{filters: filters} do
      results = Enum.map(filters, fn {size, filter} ->
        # Generate test data
        items = for i <- 1..div(size, 10) do
          "item_#{i}_#{:rand.uniform(1_000_000)}"
        end
        
        # Measure insertion time
        {time_us, _} = :timer.tc(fn ->
          Enum.each(items, &ProbabilisticFilter.add(filter, &1))
        end)
        
        time_ms = time_us / 1000
        rate = length(items) / (time_ms / 1000)
        
        %{
          filter_size: size,
          items_inserted: length(items),
          time_ms: time_ms,
          rate_per_sec: rate
        }
      end)
      
      # Performance assertions
      Enum.each(results, fn result ->
        # Should maintain at least 10k insertions/second
        assert result.rate_per_sec > 10_000
        
        # Time should scale sub-linearly
        expected_max_time = result.items_inserted / 10  # 0.1ms per item max
        assert result.time_ms < expected_max_time
      end)
      
      # Log results for analysis
      IO.puts("\nBloom Filter Insertion Performance:")
      Enum.each(results, fn r ->
        IO.puts("  Size: #{r.filter_size}, Items: #{r.items_inserted}, " <>
                "Time: #{Float.round(r.time_ms, 2)}ms, " <>
                "Rate: #{Float.round(r.rate_per_sec, 0)}/sec")
      end)
    end
    
    test "lookup performance with varying fill ratios", %{filters: filters} do
      # Test at different fill ratios
      fill_ratios = [0.1, 0.25, 0.5, 0.75, 0.9]
      
      results = for {size, filter} <- filters, ratio <- fill_ratios do
        # Fill to target ratio
        items_to_add = round(size * ratio)
        added_items = for i <- 1..items_to_add do
          item = "item_#{i}"
          ProbabilisticFilter.add(filter, item)
          item
        end
        
        # Prepare test queries (50% hits, 50% misses)
        test_items = Enum.take_random(added_items, 1000) ++
                    for(i <- 1..1000, do: "miss_#{i}")
        
        # Measure lookup performance
        {time_us, results} = :timer.tc(fn ->
          Enum.map(test_items, &ProbabilisticFilter.contains?(filter, &1))
        end)
        
        time_ms = time_us / 1000
        rate = length(test_items) / (time_ms / 1000)
        
        # Calculate accuracy
        {hits, misses} = Enum.split(results, 1000)
        true_positives = Enum.count(hits, & &1)
        false_positives = Enum.count(misses, & &1)
        
        %{
          filter_size: size,
          fill_ratio: ratio,
          lookups: length(test_items),
          time_ms: time_ms,
          rate_per_sec: rate,
          true_positive_rate: true_positives / 1000,
          false_positive_rate: false_positives / 1000
        }
      end
      
      # Performance assertions
      Enum.each(results, fn result ->
        # Lookup should be very fast
        assert result.rate_per_sec > 100_000
        
        # True positive rate should be 100%
        assert result.true_positive_rate == 1.0
        
        # False positive rate should be low
        assert result.false_positive_rate < 0.05
      end)
    end
    
    test "memory efficiency analysis", %{filters: filters} do
      memory_results = Enum.map(filters, fn {size, filter} ->
        # Get baseline memory
        :erlang.garbage_collect()
        baseline = :erlang.memory(:total)
        
        # Fill filter to 50%
        items_to_add = div(size, 2)
        for i <- 1..items_to_add do
          ProbabilisticFilter.add(filter, "item_#{i}")
        end
        
        # Measure memory after filling
        :erlang.garbage_collect()
        after_fill = :erlang.memory(:total)
        
        # Get filter stats
        stats = ProbabilisticFilter.get_stats(filter)
        
        %{
          filter_size: size,
          memory_used_bytes: after_fill - baseline,
          bits_per_element: (after_fill - baseline) * 8 / items_to_add,
          theoretical_bits: stats.bits_per_element,
          overhead_ratio: ((after_fill - baseline) * 8 / items_to_add) / stats.bits_per_element
        }
      end)
      
      # Memory efficiency assertions
      Enum.each(memory_results, fn result ->
        # Should be close to theoretical minimum
        assert result.overhead_ratio < 2.0  # Less than 2x theoretical
        
        # Bits per element should be reasonable
        assert result.bits_per_element < 20  # Less than 20 bits per element
      end)
      
      IO.puts("\nBloom Filter Memory Efficiency:")
      Enum.each(memory_results, fn r ->
        IO.puts("  Size: #{r.filter_size}, " <>
                "Bits/element: #{Float.round(r.bits_per_element, 2)}, " <>
                "Overhead: #{Float.round(r.overhead_ratio, 2)}x")
      end)
    end
  end
  
  @tag :benchmark
  describe "Neural Network Inference Performance" do
    setup do
      {:ok, neural_defender} = NeuralDefender.start_link(
        name: :benchmark_defender,
        model_type: :optimized
      )
      
      {:ok, zombie_detector} = ZombieDetector.start_link(
        name: :benchmark_zombie,
        model_type: :ensemble
      )
      
      on_exit(fn ->
        GenServer.stop(neural_defender)
        GenServer.stop(zombie_detector)
      end)
      
      %{
        neural_defender: neural_defender,
        zombie_detector: zombie_detector
      }
    end
    
    test "single inference latency", %{neural_defender: neural_defender} do
      # Test different input sizes
      input_sizes = [10, 50, 100, 500, 1000]
      
      latency_results = Enum.map(input_sizes, fn size ->
        input = for _ <- 1..size, do: :rand.uniform()
        
        # Warm up
        for _ <- 1..10 do
          NeuralDefender.predict(neural_defender, input)
        end
        
        # Measure latencies
        latencies = for _ <- 1..100 do
          {time_us, _result} = :timer.tc(fn ->
            NeuralDefender.predict(neural_defender, input)
          end)
          time_us
        end
        
        # Calculate statistics
        sorted = Enum.sort(latencies)
        p50 = Enum.at(sorted, 49)
        p95 = Enum.at(sorted, 94)
        p99 = Enum.at(sorted, 98)
        avg = Enum.sum(latencies) / length(latencies)
        
        %{
          input_size: size,
          avg_us: avg,
          p50_us: p50,
          p95_us: p95,
          p99_us: p99,
          avg_ms: avg / 1000,
          p99_ms: p99 / 1000
        }
      end)
      
      # Latency assertions
      Enum.each(latency_results, fn result ->
        # P99 should be under 10ms for real-time detection
        assert result.p99_ms < 10
        
        # Average should be under 5ms
        assert result.avg_ms < 5
      end)
      
      IO.puts("\nNeural Network Inference Latency:")
      Enum.each(latency_results, fn r ->
        IO.puts("  Input size: #{r.input_size}, " <>
                "Avg: #{Float.round(r.avg_ms, 2)}ms, " <>
                "P99: #{Float.round(r.p99_ms, 2)}ms")
      end)
    end
    
    test "batch inference throughput", %{zombie_detector: zombie_detector} do
      batch_sizes = [1, 10, 32, 64, 128, 256]
      
      throughput_results = Enum.map(batch_sizes, fn batch_size ->
        # Generate batch data
        batch = for _ <- 1..batch_size do
          %{
            features: for(_ <- 1..100, do: :rand.uniform()),
            metadata: %{timestamp: System.system_time()}
          }
        end
        
        # Measure throughput over 1 second
        iterations = 0
        start_time = System.monotonic_time(:millisecond)
        end_time = start_time + 1000
        
        iterations = Stream.repeatedly(fn ->
          ZombieDetector.batch_predict(zombie_detector, batch)
          1
        end)
        |> Stream.take_while(fn _ -> 
          System.monotonic_time(:millisecond) < end_time 
        end)
        |> Enum.sum()
        
        actual_time = System.monotonic_time(:millisecond) - start_time
        samples_processed = iterations * batch_size
        throughput = samples_processed / (actual_time / 1000)
        
        %{
          batch_size: batch_size,
          iterations: iterations,
          samples_processed: samples_processed,
          throughput_per_sec: throughput,
          efficiency: throughput / batch_size  # Batching efficiency
        }
      end)
      
      # Find optimal batch size
      optimal = Enum.max_by(throughput_results, & &1.throughput_per_sec)
      
      IO.puts("\nNeural Network Batch Throughput:")
      Enum.each(throughput_results, fn r ->
        IO.puts("  Batch: #{r.batch_size}, " <>
                "Throughput: #{Float.round(r.throughput_per_sec, 0)}/sec, " <>
                "Efficiency: #{Float.round(r.efficiency, 2)}")
      end)
      IO.puts("  Optimal batch size: #{optimal.batch_size}")
      
      # Throughput assertions
      assert optimal.throughput_per_sec > 10_000  # At least 10k samples/sec
    end
    
    test "model memory footprint", %{
      neural_defender: neural_defender,
      zombie_detector: zombie_detector
    } do
      # Get model information
      defender_info = NeuralDefender.get_model_info(neural_defender)
      zombie_info = ZombieDetector.get_model_info(zombie_detector)
      
      models = [
        {"Neural Defender", defender_info},
        {"Zombie Detector", zombie_info}
      ]
      
      memory_analysis = Enum.map(models, fn {name, info} ->
        # Calculate memory footprint
        param_memory = info.parameters * 4  # 4 bytes per float32
        activation_memory = info.max_activation_size * 4
        total_memory = param_memory + activation_memory
        
        %{
          name: name,
          parameters: info.parameters,
          layers: info.layers,
          param_memory_mb: param_memory / 1_048_576,
          activation_memory_mb: activation_memory / 1_048_576,
          total_memory_mb: total_memory / 1_048_576
        }
      end)
      
      IO.puts("\nModel Memory Footprint:")
      Enum.each(memory_analysis, fn m ->
        IO.puts("  #{m.name}: #{m.parameters} params, " <>
                "#{Float.round(m.total_memory_mb, 2)}MB total")
      end)
      
      # Memory assertions
      Enum.each(memory_analysis, fn model ->
        # Models should be compact for edge deployment
        assert model.total_memory_mb < 100  # Less than 100MB
      end)
    end
  end
  
  @tag :benchmark
  describe "Zone Routing Performance" do
    setup do
      # Create hierarchical zone structure
      {:ok, zone_router} = ZoneRouter.start_link(
        name: :benchmark_router,
        topology: :hierarchical
      )
      
      # Create test zones
      zones = for level <- 1..3, zone <- 1..10 do
        zone_id = "L#{level}_Z#{zone}"
        ZoneRouter.create_zone(zone_router, %{
          id: zone_id,
          level: level,
          capacity: 1000
        })
        zone_id
      end
      
      on_exit(fn ->
        GenServer.stop(zone_router)
      end)
      
      %{zone_router: zone_router, zones: zones}
    end
    
    test "routing decision latency", %{zone_router: zone_router, zones: zones} do
      # Test routing between different zone pairs
      test_pairs = for _ <- 1..1000 do
        {Enum.random(zones), Enum.random(zones)}
      end
      
      # Warm up router caches
      Enum.each(Enum.take(test_pairs, 100), fn {src, dst} ->
        ZoneRouter.find_route(zone_router, src, dst)
      end)
      
      # Measure routing latencies
      {total_time_us, routes} = :timer.tc(fn ->
        Enum.map(test_pairs, fn {src, dst} ->
          ZoneRouter.find_route(zone_router, src, dst)
        end)
      end)
      
      # Calculate metrics
      avg_latency_us = total_time_us / length(test_pairs)
      successful_routes = Enum.count(routes, &match?({:ok, _}, &1))
      
      routing_metrics = %{
        total_routes: length(test_pairs),
        successful_routes: successful_routes,
        success_rate: successful_routes / length(test_pairs),
        avg_latency_us: avg_latency_us,
        avg_latency_ms: avg_latency_us / 1000,
        routes_per_sec: length(test_pairs) / (total_time_us / 1_000_000)
      }
      
      IO.puts("\nZone Routing Performance:")
      IO.puts("  Routes/sec: #{Float.round(routing_metrics.routes_per_sec, 0)}")
      IO.puts("  Avg latency: #{Float.round(routing_metrics.avg_latency_ms, 3)}ms")
      IO.puts("  Success rate: #{Float.round(routing_metrics.success_rate * 100, 1)}%")
      
      # Performance assertions
      assert routing_metrics.routes_per_sec > 10_000
      assert routing_metrics.avg_latency_ms < 1
      assert routing_metrics.success_rate > 0.95
    end
    
    test "concurrent routing scalability", %{zone_router: zone_router, zones: zones} do
      # Test with increasing concurrency
      concurrency_levels = [1, 10, 50, 100, 200]
      
      scalability_results = Enum.map(concurrency_levels, fn concurrency ->
        # Create routing tasks
        tasks = for _ <- 1..concurrency do
          Task.async(fn ->
            # Each task performs 100 routing operations
            for _ <- 1..100 do
              src = Enum.random(zones)
              dst = Enum.random(zones)
              ZoneRouter.find_route(zone_router, src, dst)
            end
          end)
        end
        
        # Measure completion time
        {time_us, _} = :timer.tc(fn ->
          Task.await_many(tasks, 30_000)
        end)
        
        total_operations = concurrency * 100
        throughput = total_operations / (time_us / 1_000_000)
        
        %{
          concurrency: concurrency,
          total_operations: total_operations,
          time_ms: time_us / 1000,
          throughput_per_sec: throughput,
          speedup: throughput / (total_operations / (time_us / 1_000_000))
        }
      end)
      
      IO.puts("\nConcurrent Routing Scalability:")
      Enum.each(scalability_results, fn r ->
        IO.puts("  Concurrency: #{r.concurrency}, " <>
                "Throughput: #{Float.round(r.throughput_per_sec, 0)}/sec")
      end)
      
      # Scalability should be near-linear for reasonable concurrency
      base_throughput = hd(scalability_results).throughput_per_sec
      Enum.each(scalability_results, fn result ->
        if result.concurrency <= 50 do
          expected_min = base_throughput * result.concurrency * 0.7
          assert result.throughput_per_sec > expected_min
        end
      end)
    end
    
    test "route caching effectiveness", %{zone_router: zone_router, zones: zones} do
      # Create frequently used routes
      popular_routes = for _ <- 1..10 do
        {Enum.random(zones), Enum.random(zones)}
      end
      
      # Prime the cache
      Enum.each(popular_routes, fn {src, dst} ->
        ZoneRouter.find_route(zone_router, src, dst)
      end)
      
      # Measure cached vs uncached performance
      cached_times = for {src, dst} <- popular_routes do
        {time_us, _} = :timer.tc(fn ->
          ZoneRouter.find_route(zone_router, src, dst)
        end)
        time_us
      end
      
      uncached_times = for _ <- 1..10 do
        src = Enum.random(zones)
        dst = Enum.random(zones)
        
        # Ensure it's not in cache
        ZoneRouter.clear_cache_entry(zone_router, {src, dst})
        
        {time_us, _} = :timer.tc(fn ->
          ZoneRouter.find_route(zone_router, src, dst)
        end)
        time_us
      end
      
      avg_cached = Enum.sum(cached_times) / length(cached_times)
      avg_uncached = Enum.sum(uncached_times) / length(uncached_times)
      cache_speedup = avg_uncached / avg_cached
      
      IO.puts("\nRoute Cache Effectiveness:")
      IO.puts("  Cached avg: #{Float.round(avg_cached / 1000, 3)}ms")
      IO.puts("  Uncached avg: #{Float.round(avg_uncached / 1000, 3)}ms")
      IO.puts("  Cache speedup: #{Float.round(cache_speedup, 1)}x")
      
      # Cache should provide significant speedup
      assert cache_speedup > 5
    end
  end
  
  @tag :benchmark
  describe "System-wide Performance Integration" do
    setup do
      # Initialize all components
      {:ok, bloom} = ProbabilisticFilter.start_link(
        size: 100_000,
        name: :integration_bloom
      )
      
      {:ok, neural} = NeuralDefender.start_link(
        name: :integration_neural
      )
      
      {:ok, router} = ZoneRouter.start_link(
        name: :integration_router
      )
      
      on_exit(fn ->
        GenServer.stop(bloom)
        GenServer.stop(neural)
        GenServer.stop(router)
      end)
      
      %{bloom: bloom, neural: neural, router: router}
    end
    
    test "end-to-end request processing", %{
      bloom: bloom,
      neural: neural,
      router: router
    } do
      # Simulate realistic security check pipeline
      requests = for i <- 1..1000 do
        %{
          id: i,
          source_ip: "192.168.1.#{rem(i, 255)}",
          destination: "service_#{rem(i, 10)}",
          payload: :crypto.strong_rand_bytes(100),
          timestamp: System.system_time(:millisecond)
        }
      end
      
      # Process requests through full pipeline
      {total_time_us, results} = :timer.tc(fn ->
        Enum.map(requests, fn request ->
          # 1. Check IP against bloom filter
          ip_check = ProbabilisticFilter.contains?(bloom, request.source_ip)
          
          # 2. Neural analysis if not blacklisted
          neural_result = unless ip_check do
            features = extract_features(request)
            NeuralDefender.predict(neural, features)
          end
          
          # 3. Route to appropriate zone
          zone = determine_zone(neural_result)
          route = ZoneRouter.find_route(router, "entry", zone)
          
          %{
            request_id: request.id,
            ip_blocked: ip_check,
            threat_score: elem(neural_result || {:benign, 0}, 1),
            zone_routed: elem(route || {:ok, "default"}, 1)
          }
        end)
      end)
      
      # Calculate performance metrics
      total_ms = total_time_us / 1000
      requests_per_sec = length(requests) / (total_ms / 1000)
      avg_latency_ms = total_ms / length(requests)
      
      IO.puts("\nEnd-to-End Performance:")
      IO.puts("  Total requests: #{length(requests)}")
      IO.puts("  Total time: #{Float.round(total_ms, 2)}ms")
      IO.puts("  Throughput: #{Float.round(requests_per_sec, 0)} req/sec")
      IO.puts("  Avg latency: #{Float.round(avg_latency_ms, 3)}ms")
      
      # Performance requirements
      assert requests_per_sec > 1000  # At least 1000 req/sec
      assert avg_latency_ms < 5  # Under 5ms average
    end
  end
  
  # Helper functions
  defp extract_features(request) do
    # Extract numerical features from request
    [
      byte_size(request.payload) / 1000,
      rem(request.timestamp, 86400000) / 86400000,  # Time of day
      String.to_integer(List.last(String.split(request.source_ip, "."))) / 255,
      :erlang.phash2(request.destination, 100) / 100,
      if(byte_size(request.payload) > 500, do: 1.0, else: 0.0)
    ]
  end
  
  defp determine_zone(neural_result) do
    case neural_result do
      {:malicious, score} when score > 0.8 -> "quarantine"
      {:malicious, score} when score > 0.5 -> "restricted"
      {:suspicious, _} -> "monitored"
      _ -> "standard"
    end
  end
end