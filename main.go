package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"qwen-api-proxy/internal"
)

var (
	tokens    []internal.Token
	tokensMux sync.Mutex
	apiKey    string
)

// ChatRequest defines the structure for parsing the stream field from the request body.
type ChatRequest struct {
	Stream bool `json:"stream"`
}

// Model and ModelList structures for OpenAI compatibility
type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type ModelList struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

func startTokenRefreshRoutine() {
	ticker := time.NewTicker(4 * time.Hour)
	go func() {
		for range ticker.C {
			log.Println("Starting token refresh process...")
			tokensMux.Lock()
			var refreshedTokens []internal.Token
			for i, token := range tokens {
				newAccessToken, newRefreshToken, expiresIn, err := internal.RefreshToken(token.RefreshToken)
				if err != nil {
					log.Printf("Failed to refresh token for index %d, removing it: %v", i, err)
					continue // Skip and remove this token
				}
				if newAccessToken == "" {
					log.Printf("Refreshed token is empty for index %d, removing it.", i)
					continue // Skip and remove this token
				}

				token.AccessToken = newAccessToken
				token.RefreshToken = newRefreshToken
				if expiresIn > 0 {
					token.ExpiryDate = time.Now().Add(time.Duration(expiresIn) * time.Second).UnixMilli()
				}
				refreshedTokens = append(refreshedTokens, token)
				log.Printf("Successfully refreshed token for index %d", i)
			}
			tokens = refreshedTokens
			if err := internal.SaveTokens(tokens); err != nil {
				log.Printf("Failed to save tokens after refresh: %v", err)
			}
			tokensMux.Unlock()
			log.Println("Token refresh process finished.")
		}
	}()
}

func chatProxyHandler(w http.ResponseWriter, r *http.Request) {
	tokensMux.Lock()
	if len(tokens) == 0 {
		tokensMux.Unlock()
		http.Error(w, "No available tokens", http.StatusServiceUnavailable)
		return
	}
	tokensMux.Unlock()

	// Read the body and check for the "stream" field.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	r.Body.Close() // Close the original body

	var chatReq ChatRequest
	// We use a new reader for JSON decoding and another for the proxy.
	err = json.Unmarshal(body, &chatReq)
	if err != nil {
		// If JSON parsing fails, it might be a non-JSON request or a different structure.
		// We can proceed without setting the stream header, or handle the error as needed.
		log.Printf("Could not parse chat request body: %v", err)
	}

	// Restore the body for the proxy request.
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	target, _ := url.Parse("https://portal.qwen.ai")
	proxy := httputil.NewSingleHostReverseProxy(target)

	proxy.Director = func(req *http.Request) {
		authHeader := req.Header.Get("Authorization")
		usePoolToken := true

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			// If the token does not have the "sk-" prefix, it's an upstream access token.
			if !strings.HasPrefix(token, "sk-") {
				log.Println("Using client-provided upstream access token.")
				usePoolToken = false
			} else {
				// If it has "sk-" prefix, it's a service key and should not be forwarded.
				log.Println("Client-provided token is a service key, falling back to internal pool.")
			}
		} else {
			log.Println("No valid client-provided token, falling back to internal pool.")
		}

		if usePoolToken {
			tokensMux.Lock()
			if len(tokens) > 0 {
				selectedToken := tokens[rand.Intn(len(tokens))]
				authHeader = "Bearer " + selectedToken.AccessToken
				log.Println("Using token from internal pool for upstream request.")
			} else {
				log.Println("Warning: No token available in the pool for upstream request.")
				authHeader = "" // Ensure no invalid header is set
			}
			tokensMux.Unlock()
		}

		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		} else {
			req.Header.Del("Authorization")
		}
		req.Header.Set("User-Agent", "Go-Proxy-Client")
		req.Header.Set("Content-Type", "application/json")

		// If the client requested a stream, set the appropriate header for the upstream API.
		if chatReq.Stream {
			req.Header.Set("Accept", "text/event-stream")
		}

		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		// Rewrite path for Qwen API
		req.URL.Path = "/v1/chat/completions"
	}

	proxy.ServeHTTP(w, r)
}

func modelsHandler(w http.ResponseWriter, r *http.Request) {
	models := ModelList{
		Object: "list",
		Data: []Model{
			{
				ID:      "qwen3-coder-plus",
				Object:  "model",
				Created: time.Now().Unix(),
				OwnedBy: "qwen",
			},
			{
				ID:      "qwen3-coder-flash",
				Object:  "model",
				Created: time.Now().Unix(),
				OwnedBy: "qwen",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models)
}

func uploadTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var newToken internal.Token
	if err := json.NewDecoder(r.Body).Decode(&newToken); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if newToken.AccessToken == "" || newToken.RefreshToken == "" {
		http.Error(w, "Access token and refresh token are required", http.StatusBadRequest)
		return
	}

	// If ExpiryDate is not provided, calculate it from ExpiresIn (if available, though not in the new structure)
	// For now, we assume ExpiryDate is always provided by the client.
	if newToken.ExpiryDate == 0 {
		// This case should ideally not happen if the client provides the expiry_date.
		// We can set a default or return an error. For now, let's log a warning.
		log.Println("Warning: newToken does not have an ExpiryDate. It will be set to 0.")
	}

	tokensMux.Lock()
	defer tokensMux.Unlock()

	var found bool
	for i, token := range tokens {
		if token.RefreshToken == newToken.RefreshToken {
			tokens[i] = newToken
			found = true
			break
		}
	}

	if !found {
		tokens = append(tokens, newToken)
	}

	if err := internal.SaveTokens(tokens); err != nil {
		http.Error(w, "Failed to save token", http.StatusInternalServerError)
		log.Printf("Failed to save tokens: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token uploaded successfully"})
}

// TokenStatus defines the structure for displaying token status without exposing sensitive information.
type TokenStatus struct {
	AccessToken      string `json:"access_token_preview"`
	ExpiresAt        string `json:"expires_at"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

func tokenStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	tokensMux.Lock()
	defer tokensMux.Unlock()

	statusList := make([]TokenStatus, 0, len(tokens))
	for _, token := range tokens {
		preview := ""
		if len(token.AccessToken) > 8 {
			preview = token.AccessToken[:8] + "..."
		} else {
			preview = token.AccessToken
		}

		var expiresAtStr string
		var expiresInSeconds int64
		if token.ExpiryDate > 0 {
			expiresAtTime := time.UnixMilli(token.ExpiryDate)
			expiresAtStr = expiresAtTime.Format("2006-01-02 15:04:05")
			expiresInSeconds = int64(time.Until(expiresAtTime).Seconds())
		}

		statusList = append(statusList, TokenStatus{
			AccessToken:      preview,
			ExpiresAt:        expiresAtStr,
			ExpiresInSeconds: expiresInSeconds,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusList)
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if reqBody.RefreshToken == "" {
		http.Error(w, "refresh_token is required", http.StatusBadRequest)
		return
	}

	tokensMux.Lock()
	defer tokensMux.Unlock()

	var found bool
	for i, token := range tokens {
		if token.RefreshToken == reqBody.RefreshToken {
			newAccessToken, newRefreshToken, expiresIn, err := internal.RefreshToken(token.RefreshToken)
			if err != nil {
				http.Error(w, "Failed to refresh token", http.StatusInternalServerError)
				log.Printf("Failed to refresh token for %s: %v", token.RefreshToken, err)
				return
			}

			tokens[i].AccessToken = newAccessToken
			tokens[i].RefreshToken = newRefreshToken
			if expiresIn > 0 {
				tokens[i].ExpiryDate = time.Now().Add(time.Duration(expiresIn) * time.Second).UnixMilli()
			}

			if err := internal.SaveTokens(tokens); err != nil {
				http.Error(w, "Failed to save tokens after refresh", http.StatusInternalServerError)
				log.Printf("Failed to save tokens after refresh: %v", err)
				return
			}

			found = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "Token refreshed successfully"})
			break
		}
	}

	if !found {
		http.Error(w, "Token not found", http.StatusNotFound)
	}
}

// authMiddleware verifies the service API key from the Authorization header.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Unauthorized: Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		if token != apiKey {
			http.Error(w, "Unauthorized: Invalid API Key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	// 在程序启动时加载 API 密钥
	apiKey = internal.GetAPIKey()

	var err error
	tokens, err = internal.LoadTokens()
	if err != nil {
		log.Fatal("Failed to load tokens: ", err)
	}
	if len(tokens) == 0 {
		log.Println("Warning: No tokens loaded. The proxy will not be able to authenticate requests.")
	} else {
		log.Printf("Loaded %d tokens.", len(tokens))
	}

	rand.Seed(time.Now().UnixNano())

	go startTokenRefreshRoutine()

	// OpenAI compatible endpoints - authentication is handled inside the proxy
	http.HandleFunc("/v1/chat/completions", chatProxyHandler)
	http.HandleFunc("/v1/models", modelsHandler)

	// Management endpoints - protected by authMiddleware
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/upload-token", uploadTokenHandler)
	apiMux.HandleFunc("/api/token-status", tokenStatusHandler)
	apiMux.HandleFunc("/api/refresh-token", refreshTokenHandler)

	http.Handle("/api/", authMiddleware(apiMux))

	log.Println("Starting proxy server on :17591")
	if err := http.ListenAndServe(":17591", nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
