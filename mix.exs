defmodule VsmSecurity.MixProject do
  use Mix.Project

  def project do
    [
      app: :vsm_security,
      version: "0.1.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {VsmSecurity.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # Phoenix Framework
      {:phoenix, "~> 1.7.10"},
      {:phoenix_html, "~> 3.3"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 0.20.1"},
      {:phoenix_ecto, "~> 4.4"},
      {:phoenix_live_dashboard, "~> 0.8.2"},
      {:ecto_sql, "~> 3.10"},
      {:postgrex, ">= 0.0.0"},
      
      # Authentication
      {:guardian, "~> 2.3"},
      {:bcrypt_elixir, "~> 3.0"},
      {:comeonin, "~> 5.3"},
      
      # Neural Network Libraries
      {:nx, "~> 0.10.0"},
      {:exla, "~> 0.10.0", runtime: false},
      {:axon, "~> 0.7.0"},
      
      # Bloom Filter
      {:bloomex, "~> 1.0"},
      {:murmur, "~> 2.0"},
      
      # Security & Crypto
      {:jose, "~> 1.11"},
      {:argon2_elixir, "~> 3.0"},
      {:cloak, "~> 1.1"},
      {:ex_crypto, "~> 0.10"},
      
      # Utilities
      {:telemetry_metrics, "~> 0.6"},
      {:telemetry_poller, "~> 1.0"},
      {:gettext, "~> 0.20"},
      {:jason, "~> 1.2"},
      {:plug_cowboy, "~> 2.5"},
      {:cors_plug, "~> 3.0"},
      
      # Development & Testing
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      "assets.deploy": ["esbuild default --minify", "phx.digest"]
    ]
  end
end