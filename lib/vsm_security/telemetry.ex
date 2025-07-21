defmodule VsmSecurity.Telemetry do
  @moduledoc """
  Telemetry supervisor for monitoring and metrics collection.
  """

  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      # Telemetry poller will execute the given period measurements
      # every 10_000ms. Learn more here: https://hexdocs.pm/telemetry_metrics
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}
      # Add reporters as children of your supervision tree.
      # {Telemetry.Metrics.ConsoleReporter, metrics: metrics()}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      # Z3N Zone Metrics
      counter("vsm_security.z3n.zone.validate_access.count"),
      distribution("vsm_security.z3n.zone.validate_access.duration", unit: {:native, :millisecond}),
      summary("vsm_security.z3n.zone.trust_score"),
      
      # Neural Network Metrics
      counter("vsm_security.z3n.neural.prediction.count"),
      distribution("vsm_security.z3n.neural.prediction.duration", unit: {:native, :millisecond}),
      summary("vsm_security.z3n.neural.threat_probability"),
      
      # Network Metrics
      counter("vsm_security.z3n.network.messages.sent"),
      counter("vsm_security.z3n.network.messages.received"),
      summary("vsm_security.z3n.network.latency", unit: {:native, :millisecond}),
      summary("vsm_security.z3n.network.connections.active"),
      
      # Bloom Filter Metrics
      counter("vsm_security.bloom_filter.add.count"),
      counter("vsm_security.bloom_filter.check.count"),
      summary("vsm_security.bloom_filter.false_positive_rate"),
      
      # System Metrics
      summary("vm.memory.total", unit: {:byte, :megabyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io")
    ]
  end

  defp periodic_measurements do
    [
      # A module, function and arguments to be invoked periodically.
      {VsmSecurity.Telemetry.Measurements, :dispatch_metrics, []}
    ]
  end
end

defmodule VsmSecurity.Telemetry.Measurements do
  @moduledoc """
  Custom measurements for periodic telemetry events.
  """

  def dispatch_metrics do
    # Memory metrics
    memory = :erlang.memory()
    :telemetry.execute([:vm, :memory], %{total: memory[:total]}, %{})

    # Run queue lengths
    run_queue = :erlang.statistics(:run_queue_lengths)
    :telemetry.execute(
      [:vm, :total_run_queue_lengths],
      %{
        total: Enum.sum(run_queue[:run_queue_lengths]),
        cpu: length(run_queue[:run_queue_lengths]),
        io: 0
      },
      %{}
    )
  end
end