# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :vsm_security,
  namespace: VsmSecurity,
  ecto_repos: [VsmSecurity.Repo]

# Configures the endpoint
config :vsm_security, VsmSecurityWeb.Endpoint,
  url: [host: "localhost"],
  render_errors: [
    formats: [html: VsmSecurityWeb.ErrorHTML, json: VsmSecurityWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: VsmSecurity.PubSub,
  live_view: [signing_salt: "vH7Rp3Nz"]

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.17.11",
  vsm_security: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "3.4.0",
  vsm_security: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Guardian configuration for JWT
config :vsm_security, VsmSecurity.Guardian,
  issuer: "vsm_security",
  secret_key: "your-secret-key-here"  # Change this in production!

# Z3N Configuration
config :vsm_security, :z3n,
  max_zones: 100,
  default_trust_score: 50,
  threat_model_update_interval: :timer.minutes(5),
  neural_model_params: %{
    learning_rate: 0.001,
    batch_size: 32,
    hidden_layers: [256, 128, 64]
  }

# Bloom Filter Configuration
config :vsm_security, :bloom_filters,
  default_preset: :medium,
  auto_resize: true,
  persistence_enabled: true

# Neural Network Configuration
config :vsm_security, :neural,
  backend: EXLA.Backend,
  default_defn_options: [compiler: EXLA]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"