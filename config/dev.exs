import Config

# Configure your database
config :vsm_security, VsmSecurity.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "vsm_security_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

# For development, we disable any cache and enable
# debugging and code reloading.
#
# The watchers configuration can be used to run external
# watchers to your application. For example, we can use it
# to bundle .js and .css sources.
config :vsm_security, VsmSecurityWeb.Endpoint,
  # Binding to loopback ipv4 address prevents access from other machines.
  # Change to `ip: {0, 0, 0, 0}` to allow access from other machines.
  http: [ip: {127, 0, 0, 1}, port: 4000],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base: "iHxsMxg8OFQe0VvCPxQ+BmHSyTZG3nR8VnGzN4J5+KzF5EQWvH2MKJe7YvPLxXnR",
  watchers: [
    esbuild: {Esbuild, :install_and_run, [:vsm_security, ~w(--sourcemap=inline --watch)]},
    tailwind: {Tailwind, :install_and_run, [:vsm_security, ~w(--watch)]}
  ]

# Watch static and templates for browser reloading.
config :vsm_security, VsmSecurityWeb.Endpoint,
  live_reload: [
    patterns: [
      ~r"priv/static/(?!uploads/).*(js|css|png|jpeg|jpg|gif|svg)$",
      ~r"lib/vsm_security_web/(controllers|live|components)/.*(ex|heex)$"
    ]
  ]

# Enable dev routes for dashboard and mailbox
config :vsm_security, dev_routes: true

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime

# Include HEEx debug annotations as HTML comments in rendered markup
config :phoenix_live_view, :debug_heex_annotations, true