defmodule VSMSecurity.Auth.Guardian do
  @moduledoc """
  Guardian implementation for VSM Security authentication.
  Provides JWT-based authentication with Z3N security integration.
  """
  use Guardian, otp_app: :vsm_security

  alias VSMSecurity.Auth.User
  alias VSMSecurity.Z3N
  alias VSMSecurity.Z3N.Zone

  @doc """
  Subject for token based on user struct
  """
  def subject_for_token(%User{id: id}, _claims) do
    # Include zone information in subject
    zone = Zone.get_user_zone(id)
    {:ok, "#{id}:#{zone}"}
  end

  def subject_for_token(_, _) do
    {:error, :invalid_resource}
  end

  @doc """
  Resource from token subject
  """
  def resource_from_claims(%{"sub" => sub}) do
    case String.split(sub, ":") do
      [id, zone] ->
        # Verify user still has access to claimed zone
        with {:ok, user} <- User.get(id),
             true <- Zone.verify_access(user, zone) do
          {:ok, user}
        else
          _ -> {:error, :invalid_token}
        end
      
      _ ->
        {:error, :invalid_token}
    end
  end

  def resource_from_claims(_) do
    {:error, :invalid_claims}
  end

  @doc """
  Verify claims with Z3N security
  """
  def verify_claims(claims, _opts) do
    with {:ok, _} <- verify_expiration(claims),
         {:ok, _} <- verify_z3n_security(claims),
         {:ok, _} <- verify_neural_signature(claims) do
      {:ok, claims}
    end
  end

  defp verify_expiration(%{"exp" => exp}) do
    if exp > System.system_time(:second) do
      {:ok, :valid}
    else
      {:error, :token_expired}
    end
  end

  defp verify_expiration(_), do: {:error, :missing_expiration}

  defp verify_z3n_security(claims) do
    # Verify token hasn't been used in attacks
    case Z3N.verify_token_security(claims) do
      :safe -> {:ok, :verified}
      :suspicious -> {:error, :suspicious_activity}
      :threat -> {:error, :security_threat}
    end
  end

  defp verify_neural_signature(claims) do
    # Use neural network to verify token pattern
    case Z3N.Neural.verify_token_pattern(claims) do
      {:ok, confidence} when confidence > 0.95 -> {:ok, :verified}
      _ -> {:error, :abnormal_pattern}
    end
  end

  @doc """
  Build custom claims with security metadata
  """
  def build_claims(claims, resource, _opts) do
    claims
    |> Map.put("zone", Zone.get_user_zone(resource.id))
    |> Map.put("security_level", calculate_security_level(resource))
    |> Map.put("neural_sig", generate_neural_signature(resource))
    |> Map.put("iat", System.system_time(:second))
  end

  defp calculate_security_level(user) do
    # Calculate based on user history and current threat level
    base_level = user.trust_score || 50
    threat_adjustment = Z3N.get_threat_level() * -10
    
    max(0, min(100, base_level + threat_adjustment))
  end

  defp generate_neural_signature(user) do
    # Generate unique neural signature for this session
    Z3N.Neural.generate_session_signature(user)
  end

  @doc """
  Token validation hook
  """
  def on_verify(claims, token, _opts) do
    # Log verification for analysis
    VSMSecurity.Telemetry.execute(
      [:auth, :token, :verified],
      %{count: 1},
      %{claims: claims, token: token}
    )
    
    {:ok, claims}
  end

  @doc """
  Token revocation check
  """
  def on_revoke(claims, token, _opts) do
    # Add to bloom filter for quick revocation checks
    VSMSecurity.BloomFilters.ThreatFilter.add_revoked_token(token)
    
    VSMSecurity.Telemetry.execute(
      [:auth, :token, :revoked],
      %{count: 1},
      %{claims: claims}
    )
    
    {:ok, claims}
  end
end