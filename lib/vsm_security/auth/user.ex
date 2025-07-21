defmodule VSMSecurity.Auth.User do
  @moduledoc """
  User struct for authentication
  """
  
  defstruct [
    :id,
    :email,
    :trust_score,
    :zone,
    :permissions,
    :metadata
  ]

  @type t :: %__MODULE__{
    id: String.t(),
    email: String.t(),
    trust_score: integer(),
    zone: atom(),
    permissions: list(String.t()),
    metadata: map()
  }

  @doc """
  Get a user by ID (placeholder - in production this would query a database)
  """
  def get(id) do
    # Placeholder implementation
    {:ok, %__MODULE__{
      id: id,
      email: "user@example.com",
      trust_score: 50,
      zone: :public,
      permissions: ["read"],
      metadata: %{}
    }}
  end

  @doc """
  Verify user has required permissions
  """
  def has_permission?(%__MODULE__{permissions: permissions}, permission) do
    permission in permissions
  end

  @doc """
  Update user trust score
  """
  def update_trust_score(%__MODULE__{} = user, adjustment) do
    new_score = max(0, min(100, user.trust_score + adjustment))
    %{user | trust_score: new_score}
  end
end