package internal

import (
	"encoding/json"
	"io/ioutil"
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
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
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
	qwenOauthClientID = "qwen-web"
)

// RefreshToken sends a request to refresh the access token.
func RefreshToken(refreshToken string) (string, string, int, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", qwenOauthClientID)

	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", 0, err
	}

	var refreshResp RefreshResponse
	if err := json.Unmarshal(body, &refreshResp); err != nil {
		return "", "", 0, err
	}

	newAccessToken := refreshResp.AccessToken
	newRefreshToken := refreshToken // Default to old refresh token
	if refreshResp.RefreshToken != "" {
		newRefreshToken = refreshResp.RefreshToken
	}

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
