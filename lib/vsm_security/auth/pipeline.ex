defmodule VSMSecurity.Auth.Pipeline do
  @moduledoc """
  Authentication pipeline with Z3N security integration.
  Implements zero-trust verification at every stage.
  """
  use Guardian.Plug.Pipeline,
    otp_app: :vsm_security,
    error_handler: VSMSecurity.Auth.ErrorHandler,
    module: VSMSecurity.Auth.Guardian

  # Zero-trust: verify everything
  plug Guardian.Plug.VerifySession, claims: %{"typ" => "access"}
  plug Guardian.Plug.VerifyHeader, claims: %{"typ" => "access"}
  plug Guardian.Plug.LoadResource, allow_blank: true
  
  # Z3N Security layers
  plug VSMSecurity.Auth.Plugs.VerifyZone
  plug VSMSecurity.Auth.Plugs.NeuralCheck
  plug VSMSecurity.Auth.Plugs.ZombieDetection
  plug VSMSecurity.Auth.Plugs.RateLimiter
end

defmodule VSMSecurity.Auth.ErrorHandler do
  @moduledoc """
  Handles authentication errors with security logging
  """
  @behaviour Guardian.Plug.ErrorHandler

  import Plug.Conn
  alias VSMSecurity.Z3N

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {type, reason}, _opts) do
    # Log security event
    Z3N.log_security_event(:auth_error, %{
      type: type,
      reason: reason,
      ip: get_peer_ip(conn),
      path: conn.request_path
    })

    # Check if this is part of an attack
    if Z3N.detect_auth_attack_pattern(conn) do
      # Trigger defensive measures
      Z3N.activate_defense_mode(get_peer_ip(conn))
    end

    body = Jason.encode!(%{
      error: %{
        type: to_string(type),
        message: translate_error(type, reason)
      }
    })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, body)
  end

  defp get_peer_ip(conn) do
    case Plug.Conn.get_peer_data(conn) do
      %{address: {a, b, c, d}} -> "#{a}.#{b}.#{c}.#{d}"
      _ -> "unknown"
    end
  end

  defp translate_error(:invalid_token, _), do: "Invalid authentication token"
  defp translate_error(:token_expired, _), do: "Authentication token has expired"
  defp translate_error(:no_resource_found, _), do: "User not found"
  defp translate_error(:unauthenticated, _), do: "Authentication required"
  defp translate_error(:already_authenticated, _), do: "Already authenticated"
  defp translate_error(_, _), do: "Authentication error"
end