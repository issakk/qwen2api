# Qwen API Proxy (Go Version)

This project is a Qwen API proxy service written in Go.

## How to Run

1.  **Install Go**: Make sure you have the Go programming language installed on your system.
2.  **Navigate to Directory**: Open your terminal and navigate to the `go-rewrite` directory.
3.  **Set API Key**: Before running the service, you **must** set your secret service API key. This key is used to protect the administrative endpoints. Open the appropriate script for your operating system (`run.bat` for Windows, `run.sh` for Linux/macOS) and replace `your_secret_api_key_here` with a key that **must** start with the prefix `sk-`.
4.  **Run the Script**:
    *   On **Windows**, run the command:
        ```bash
        run.bat
        ```
    *   On **Linux/macOS**, make the script executable first, then run it:
        ```bash
        chmod +x run.sh
        ./run.sh
        ```

The service will start on port `8080`.

## API Usage

All API endpoints use a unified authentication method via the `Authorization: Bearer {token}` header. The type of token you provide determines which endpoints you can access.

### Authentication

#### 1. Service API Key (for `/api/*` endpoints)

Used for administrative tasks like uploading and viewing tokens. This key **must** have the `sk-` prefix.

*   **Endpoints**:
    *   `/api/upload-token`
    *   `/api/token-status`
*   **Usage**: Provide the service API key you configured in the `run` script.

**Example**:
`Authorization: Bearer sk-your_service_api_key`

#### 2. Upstream Access Token (for `/v1/*` endpoints)

Used for accessing the OpenAI-compatible endpoints that proxy requests to the upstream service (e.g., Qwen). This token is your actual access token from the upstream provider and **should not** have the `sk-` prefix.

*   **Endpoints**:
    *   `/v1/chat/completions`
    *   `/v1/models`
*   **Usage**: Provide your upstream `access_token`.

**Example**:
`Authorization: Bearer {qwen_access_token}`

If you do not provide an `Authorization` header or if you provide a service key (with `sk-` prefix), the service will automatically use a token from its internal pool to process the request.