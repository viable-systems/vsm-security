defmodule VsmSecurity.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the PubSub system
      {Phoenix.PubSub, name: VsmSecurity.PubSub},
      
      # Start a registry for Z3N zones
      {Registry, keys: :unique, name: VsmSecurity.Z3N.Registry},
      
      # Start the Z3N Network manager
      VsmSecurity.Z3N.Network,
      
      # Start a dynamic supervisor for Z3N zones
      {DynamicSupervisor, name: VsmSecurity.Z3N.ZoneSupervisor, strategy: :one_for_one},
      
      # Start the Telemetry supervisor
      VsmSecurity.Telemetry,
      
      # Start the Endpoint (http/https)
      # VsmSecurity.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: VsmSecurity.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    # VsmSecurity.Endpoint.config_change(changed, removed)
    :ok
  end
end