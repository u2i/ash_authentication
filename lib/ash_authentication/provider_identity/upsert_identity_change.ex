defmodule AshAuthentication.ProviderIdentity.UpsertIdentityChange do
  @moduledoc """
  A change which upserts a user's identity into the identity provider resource.

  Expects the following arguments:

    - `user_info` a map with string keys as returned from the OAuth2/OpenID
      upstream provider.
    - `oauth_tokens` a map with string keys containing the OAuth2 token
      response.
    - `user_id` the ID of the user this identity relates to.
    - `provider` the name of the provider.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.ProviderIdentity.Info

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    cfg = Info.options(changeset.resource)

    user_info = Changeset.get_argument(changeset, :user_info)
    oauth_tokens = Changeset.get_argument(changeset, :oauth_tokens)
    user_id = Changeset.get_argument(changeset, cfg.user_id_attribute_name)

    uid =
      user_info
      |> Map.take(["uid", "sub"])
      |> Map.values()
      |> Enum.reject(&is_nil/1)
      |> List.first()

    changeset
    |> Changeset.change_attribute(cfg.user_id_attribute_name, user_id)
    |> Changeset.change_attribute(cfg.uid_attribute_name, uid)
    |> Changeset.change_attribute(
      cfg.access_token_attribute_name,
      Map.get(oauth_tokens, "access_token")
    )
    |> Changeset.change_attribute(
      cfg.access_token_expires_at_attribute_name,
      expires_at(oauth_tokens, "expires_in")
    )
    |> Changeset.change_attribute(
      cfg.refresh_token_attribute_name,
      Map.get(oauth_tokens, "refresh_token")
    )
  end

  defp expires_at(oauth_tokens, field) do
    oauth_tokens
    |> Map.get(field)
    |> case do
      nil ->
        nil

      expires_in when is_binary(expires_in) ->
        expires_in
        |> String.to_integer()
        |> from_now()

      expires_in when is_number(expires_in) ->
        expires_in
        |> from_now()
    end
  end

  defp from_now(seconds) do
    DateTime.utc_now()
    |> DateTime.add(seconds, :second)
  end
end
