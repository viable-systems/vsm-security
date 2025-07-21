import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
# Disable Ecto repo for now since we're not using a database yet
# config :vsm_security, VsmSecurity.Repo,
#   username: "postgres",
#   password: "postgres",
#   hostname: "localhost",
#   database: "vsm_security_test#{System.get_env("MIX_TEST_PARTITION")}",
#   pool: Ecto.Adapters.SQL.Sandbox,
#   pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :vsm_security, VsmSecurityWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "testKeyBase+BmHSyTZG3nR8VnGzN4J5+KzF5EQWvH2MKJe7YvPLxXnR",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Disable swoosh api client as it is only required for production adapters.
config :swoosh, :api_client, false

# Configure Guardian for tests
config :vsm_security, VSMSecurity.Auth.Guardian,
  issuer: "vsm_security_test",
  secret_key: "test_secret_key_for_testing_only"

# Configure EXLA to use host/CPU
config :exla, :clients,
  default: [platform: :host],
  host: [platform: :host]