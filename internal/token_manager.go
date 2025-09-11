package internal

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Token represents the structure for access and refresh tokens.
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiryDate   int64  `json:"expiry_date"`
}

// RefreshResponse defines the structure for the new token refresh API response.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

const (
	dbDir             = "database"
	tokensFile        = "tokens.json"
	refreshURL        = "https://chat.qwen.ai/api/v1/oauth2/token"
	qwenOauthClientID = "f0304373b74a44d2b584a3fb70ca9e56"
)

// RefreshToken sends a request to refresh the access token.
func RefreshToken(refreshToken string) (string, string, int, error) {
	log.Printf("Attempting to refresh token: %s...", refreshToken[:10]) // Log first 10 chars for identification
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", qwenOauthClientID)

	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Failed to create refresh request: %v", err)
		return "", "", 0, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send refresh request: %v", err)
		return "", "", 0, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read refresh response body: %v", err)
		return "", "", 0, err
	}
	log.Printf("Refresh token response body: %s", string(body))

	var refreshResp RefreshResponse
	if err := json.Unmarshal(body, &refreshResp); err != nil {
		log.Printf("Failed to unmarshal refresh response: %v. Body: %s", err, string(body))
		return "", "", 0, err
	}

	newAccessToken := refreshResp.AccessToken
	newRefreshToken := refreshToken // Default to old refresh token
	if refreshResp.RefreshToken != "" {
		newRefreshToken = refreshResp.RefreshToken
	}

	log.Printf("Token refreshed successfully. New Access Token Preview: %s...", newAccessToken[:8])
	return newAccessToken, newRefreshToken, refreshResp.ExpiresIn, nil
}

// SaveTokens saves a slice of Tokens to the database/tokens.json file.
// It creates the directory if it does not exist.
func SaveTokens(tokens []Token) error {
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(dbDir, tokensFile)
	return ioutil.WriteFile(filePath, data, 0644)
}

// LoadTokens loads a slice of Tokens from the database/tokens.json file.
func LoadTokens() ([]Token, error) {
	filePath := filepath.Join(dbDir, tokensFile)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return []Token{}, nil
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var tokens []Token
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}
