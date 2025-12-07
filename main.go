package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func getIp(c *gin.Context) {
	ip_address := c.Param("ip")

	rdb := c.MustGet("redis").(*redis.Client)

	cacheKey := fmt.Sprintf("analysis:ip:%s", ip_address)

	val, err := rdb.Get(c, cacheKey).Result()
	if err == nil {
		c.Header("X-Cache-Status", "HIT")

		c.Data(http.StatusOK, "application/json", []byte(val))
		return
	}

	results := map[string]interface{}{
		"virustotal":     virustotalAnalyze("ip_addresses/" + ip_address),
		"abuseipdb":      abuseipdbAnalyze(ip_address),
		"alienvault_otx": alienvaultAnalyze(ip_address),
		"ipqualityscore": ipqualityscoreAnalyze(ip_address),
	}

	jsonBytes, err := json.Marshal(results)
	if err != nil {
		log.Println("JSON Error:", err)
	} else {
		err = rdb.Set(context.Background(), cacheKey, jsonBytes, 12*time.Hour).Err()
		if err != nil {
			log.Println("Redis Cache Error:", err)
		}
	}

	c.Data(http.StatusOK, "application/json", jsonBytes)
}
func virustotalAnalyze(request string) any {
	url := "https://www.virustotal.com/api/v3/" + request
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", os.Getenv("VT_API_KEY"))
	return makeRequest(req)
}

func abuseipdbAnalyze(ip string) any {
	url := "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Key", os.Getenv("ABUSEIPDB_API_KEY"))
	req.Header.Add("Accept", "application/json")
	return makeRequest(req)
}

func alienvaultAnalyze(ip string) any {
	url := "https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/general"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", os.Getenv("ALIENVAULT_API_KEY"))
	return makeRequest(req)
}

func ipqualityscoreAnalyze(ip string) any {
	url := "https://ipqualityscore.com/api/json/ip/" + os.Getenv("IPQUALITYSCORE_API_KEY") + "/" + ip
	req, _ := http.NewRequest("GET", url, nil)
	return makeRequest(req)
}

func getDomain(c *gin.Context) {
	domain := c.Param("domain")

	rdb := c.MustGet("redis").(*redis.Client)
	cacheKey := fmt.Sprintf("analysis:domain:%s", domain)

	val, err := rdb.Get(c, cacheKey).Result()
	if err == nil {
		c.Header("X-Cache-Status", "HIT")
		c.Data(http.StatusOK, "application/json", []byte(val))
		return
	}

	results := map[string]interface{}{
		"virustotal":     virustotalAnalyze("domains/" + domain),
		"alienvault_otx": alienvaultDomainAnalyze(domain),
	}

	jsonBytes, _ := json.Marshal(results)
	rdb.Set(context.Background(), cacheKey, jsonBytes, 12*time.Hour)

	c.Data(http.StatusOK, "application/json", jsonBytes)
}

func alienvaultDomainAnalyze(domain string) any {
	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/general"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", os.Getenv("ALIENVAULT_API_KEY"))
	return makeRequest(req)
}

func getAPT(c *gin.Context) {
	aptName := c.Param("apt")

	rdb := c.MustGet("redis").(*redis.Client)
	cacheKey := fmt.Sprintf("analysis:apt:%s", aptName)

	val, err := rdb.Get(c, cacheKey).Result()
	if err == nil {
		c.Header("X-Cache-Status", "HIT")
		c.Data(http.StatusOK, "application/json", []byte(val))
		return
	}

	results := map[string]interface{}{
		"alienvault_otx": aptAlienvaultAnalyze(aptName),
	}

	jsonBytes, _ := json.Marshal(results)
	rdb.Set(context.Background(), cacheKey, jsonBytes, 24*time.Hour)

	c.Data(http.StatusOK, "application/json", jsonBytes)
}

func aptAlienvaultAnalyze(aptName string) any {
	url := "https://otx.alienvault.com/api/v1/search/pulses?q=" + aptName
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-OTX-API-KEY", os.Getenv("ALIENVAULT_API_KEY"))
	return makeRequest(req)
}

func makeRequest(req *http.Request) any {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	var result any
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]string{"error": "invalid json", "raw": string(body)}
	}
	return result
}

func apiKeyAuth(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("x-api-key")

		var active bool
		var err error
		var limit int
		err = pool.QueryRow(context.Background(),
			"SELECT active, rate_limit_per_day FROM users WHERE api_key = $1", apiKey).Scan(&active, &limit)

		if err == pgx.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Database error"})
			c.Abort()
			return
		}

		if !active {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "You account is not active"})
			c.Abort()
			return
		}

		c.Set("limit", limit)

		c.Next()
	}
}

func checkRateLimit(rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := c.GetInt("limit")
		if limit == 0 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Limit not defined"})
			return
		}

		apiKey := c.GetHeader("x-api-key")
		key := fmt.Sprintf("rate_limit:%s:%s", apiKey, time.Now().Format("2006-01-02"))

		count, err := rdb.Incr(context.Background(), key).Result()
		if err != nil {
			fmt.Println("REDIS ERROR:", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Rate limit service error"})
			return
		}

		if count == 1 {
			rdb.Expire(context.Background(), key, 24*time.Hour)
		}

		if count > int64(limit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Daily API limit reached",
				"limit": limit,
			})
			return
		}

		c.Set("redis", rdb)
		c.Next()
	}
}

func main() {
	godotenv.Load()

	neonConnUrl := os.Getenv("NEON_DATABASE_URL")

	pool, err := pgxpool.New(context.Background(), neonConnUrl)
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
	defer pool.Close()

	redisURL := os.Getenv("REDIS_URL")
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatal(err)
	}
	rdb := redis.NewClient(opt)

	router := gin.Default()

	router.GET("/api/v1/check/ip/:ip", apiKeyAuth(pool), checkRateLimit(rdb), getIp)
	router.GET("/api/v1/check/domain/:domain", apiKeyAuth(pool), checkRateLimit(rdb), getDomain)
	router.GET("/api/v1/check/apt/:apt", apiKeyAuth(pool), checkRateLimit(rdb), getAPT)

	router.Run()
}
