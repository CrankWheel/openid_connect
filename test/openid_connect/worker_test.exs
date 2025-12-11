defmodule OpenIDConnect.WorkerTest do
  use ExUnit.Case
  import Mox

  setup :set_mox_global
  setup :verify_on_exit!

  @google_document Fixtures.load(:google, :discovery_document)
  @google_certs Fixtures.load(:google, :certs)

  alias OpenIDConnect.{HTTPClientMock}

  test "starting with :ignore does nothing" do
    :ignore = OpenIDConnect.Worker.start_link(:ignore)
  end

  test "starting with a single provider will retrieve the necessary documents" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    state = :sys.get_state(pid)

    expected_document =
      @google_document
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> OpenIDConnect.normalize_discovery_document()

    expected_jwk =
      @google_certs
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> JOSE.JWK.from()

    assert expected_document == get_in(state, [:google, :documents, :discovery_document])
    assert expected_jwk == get_in(state, [:google, :documents, :jwk])
  end

  test "worker can respond to a call for the config" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    google_config = GenServer.call(pid, {:config, :google})

    assert get_in(config, [:google]) == google_config
  end

  test "worker started using callback function can respond to a call for the config" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, {:callback, fn ->
      config
    end}})

    google_config = GenServer.call(pid, {:config, :google})

    assert get_in(config, [:google]) == google_config
  end

  test "worker can respond to a call for a provider's discovery document" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    discovery_document = GenServer.call(pid, {:discovery_document, :google})

    expected_document =
      @google_document
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> OpenIDConnect.normalize_discovery_document()

    assert expected_document == discovery_document
  end

  test "worker can respond to a call for a provider's jwk" do
    mock_http_requests()

    config = Application.get_env(:openid_connect, :providers)

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    jwk = GenServer.call(pid, {:jwk, :google})

    expected_jwk =
      @google_certs
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> JOSE.JWK.from()

    assert expected_jwk == jwk
  end

  test "worker continues running when a provider fails to fetch documents" do
    mock_http_internet_down()

    config = Application.get_env(:openid_connect, :providers)

    # Worker should start successfully even when HTTP requests fail
    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    # Worker should still be running and respond to calls
    state = :sys.get_state(pid)

    # The provider should have error state instead of documents
    assert %{error: :update_documents} = get_in(state, [:google, :documents])
  end

  test "worker handles mixed success/failure across multiple providers" do
    # First provider (google) succeeds, second provider (failing) fails
    HTTPClientMock
    |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration", _headers, _opts ->
      @google_document
    end)
    |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, _opts ->
      @google_certs
    end)
    |> expect(:get, fn "https://failing.example.com/.well-known/openid-configuration", _headers, _opts ->
      {:error, %HTTPoison.Error{id: nil, reason: :nxdomain}}
    end)

    config = [
      google: Application.get_env(:openid_connect, :providers)[:google],
      failing: [
        discovery_document_uri: "https://failing.example.com/.well-known/openid-configuration",
        client_id: "test",
        client_secret: "test"
      ]
    ]

    {:ok, pid} = start_supervised({OpenIDConnect.Worker, config})

    state = :sys.get_state(pid)

    # Google should have valid documents
    expected_document =
      @google_document
      |> elem(1)
      |> Map.get(:body)
      |> Jason.decode!()
      |> OpenIDConnect.normalize_discovery_document()

    assert expected_document == get_in(state, [:google, :documents, :discovery_document])

    # Failing provider should have error state
    assert %{error: :update_documents} = get_in(state, [:failing, :documents])
  end

  defp mock_http_requests do
    HTTPClientMock
    |> expect(:get, fn "https://accounts.google.com/.well-known/openid-configuration", _headers, _opts ->
      @google_document
    end)
    |> expect(:get, fn "https://www.googleapis.com/oauth2/v3/certs", _headers, _opts -> @google_certs end)
  end

  defp mock_http_internet_down do
    # Only one call expected - if discovery document fetch fails, certs won't be fetched
    HTTPClientMock
    |> expect(:get, fn _, _, _ ->
      {:error, %HTTPoison.Error{id: nil, reason: :nxdomain}}
    end)
  end
end
