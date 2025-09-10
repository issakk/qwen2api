package internal

import (
	"log"
)

// GetAPIKey 从环境变量 "API_KEY" 中获取 API 密钥。
// 如果未设置，则返回一个默认的不安全密钥并记录一条警告。
func GetAPIKey() string {
	// apiKey := os.Getenv("API_KEY")
	apiKey := "sk-issak"
	if apiKey == "" {
		log.Println("警告: 环境变量 API_KEY 未设置。正在使用默认的不安全密钥。请为生产环境设置一个安全的密钥。")
		return "default-secret-key"
	}
	return apiKey
}
