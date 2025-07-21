ExUnit.start()

# Configure ExUnit for security testing
ExUnit.configure(
  capture_log: true,
  trace: true,
  max_failures: 5,
  timeout: 60_000  # 60 seconds for complex security tests
)

# Define custom assertions for security tests
defmodule VSM.Security.TestHelpers do
  import ExUnit.Assertions
  
  @doc """
  Assert that a security event was triggered
  """
  def assert_security_event(event_type, timeout \\ 1000) do
    assert_receive {:security_event, ^event_type, _details}, timeout
  end
  
  @doc """
  Assert that a neural alert was triggered
  """
  def assert_neural_alert(alert_type, min_confidence \\ 0.8) do
    assert_receive {:neural_alert, ^alert_type, details}
    assert details.confidence >= min_confidence
  end
  
  @doc """
  Assert that defense was activated
  """
  def assert_defense_activated(defense_type) do
    assert_receive {:defense_activated, ^defense_type}
  end
  
  @doc """
  Assert performance within bounds
  """
  def assert_performance(metric, max_value, unit \\ :milliseconds) do
    assert metric <= max_value, 
      "Performance assertion failed: #{metric}#{unit} exceeds #{max_value}#{unit}"
  end
end

# Start any required applications
Application.ensure_all_started(:crypto)
Application.ensure_all_started(:ssl)
