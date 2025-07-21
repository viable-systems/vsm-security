defmodule SecurityAlert do
  @moduledoc """
  Security alert notification system for VSM Security
  """
  
  require Logger
  
  @doc """
  Send a security alert
  """
  def send(alert) do
    Logger.error("[SECURITY ALERT] #{alert.type} - Severity: #{alert.severity}")
    Logger.error("Node: #{alert.node_id}")
    Logger.error("Reason: #{inspect(alert.reason)}")
    Logger.error("Actions taken: #{inspect(alert.actions_taken)}")
    Logger.error("Timestamp: #{alert.timestamp}")
    
    # In production, this would send to monitoring systems, 
    # security teams, etc.
    :ok
  end
end