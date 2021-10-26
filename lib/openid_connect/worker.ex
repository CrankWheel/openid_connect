defmodule OpenIDConnect.Worker do
  use GenServer

  @moduledoc """
  Worker module for OpenID Connect

  This worker will store and periodically update each provider's documents and JWKs according to the lifetimes
  """

  @refresh_time 60 * 60 * 1000

  def start_link(provider_configs, name \\ :openid_connect) do
    GenServer.start_link(__MODULE__, provider_configs, name: name)
  end

  def init(:ignore) do
    :ignore
  end

  def init(provider_configs) do
    # We do not actually fetch the documents at this point, since failing at
    # init time can prevent an entire Elixir application from starting.
    #
    # However, the first messages this process receives will cause it to try
    # to retrieve the configs, and the worker can fail at that point, to be
    # handled by its supervisor however it chooses (e.g. try restarting within
    # X seconds, or just treat it as a temporary worker - up to the application).
    state =
      Enum.into(provider_configs, %{}, fn {provider, config} ->
        Process.send(self(), {:update_documents, provider}, [])
        {provider, %{config: config, documents: %{}}}
      end)

    {:ok, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    discovery_document = get_in(state, [provider, :documents, :discovery_document])
    {:reply, discovery_document, state}
  end

  def handle_call({:jwk, provider}, _from, state) do
    jwk = get_in(state, [provider, :documents, :jwk])
    {:reply, jwk, state}
  end

  def handle_call({:config, provider}, _from, state) do
    config = get_in(state, [provider, :config])
    {:reply, config, state}
  end

  def handle_info({:update_documents, provider}, state) do
    config = get_in(state, [provider, :config])
    documents = update_documents(provider, config)

    state = put_in(state, [provider, :documents], documents)

    {:noreply, state}
  end

  defp update_documents(provider, config) do
    {:ok, %{remaining_lifetime: remaining_lifetime}} =
      {:ok, documents} = OpenIDConnect.update_documents(config)

    refresh_time = time_until_next_refresh(remaining_lifetime)

    Process.send_after(self(), {:update_documents, provider}, refresh_time)

    documents
  end

  defp time_until_next_refresh(nil), do: @refresh_time

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds > 0,
    do: :timer.seconds(time_in_seconds)

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds <= 0, do: 0
end
