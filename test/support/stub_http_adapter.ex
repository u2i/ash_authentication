# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule StubHTTPAdapter do
  @moduledoc """
  A real `Assent.HTTPAdapter` so tests can drive Assent's own strategy
  callbacks end to end instead of stubbing the strategy module. Responses
  are looked up from the process dictionary (set via `stub/2`), keyed by
  request URL.
  """
  @behaviour Assent.HTTPAdapter

  def stub(url, response), do: Process.put({__MODULE__, url}, response)

  @impl true
  def request(_method, url, _body, _headers, _opts) do
    case Process.get({__MODULE__, url}) do
      nil -> {:error, %Assent.HTTPAdapter.HTTPResponse{status: 404, body: %{}}}
      response -> {:ok, response}
    end
  end
end
