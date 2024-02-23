package ratelimiter
//
import (
    "context"
    "fmt"
    "net/http"
    "os"
    "strconv"
    "strings"

    "github.com/golang-jwt/jwt"
    "github.com/redis/go-redis/v9"
)

type Limiter interface {
    CheckRateLimit(r *http.Request) error
}

type RedisRateLimiter struct {
    client *redis.Client
}

func NewRedisRateLimiter(client *redis.Client) (*RedisRateLimiter, error) {
    fmt.Println("Running rate limiter ... ")
    if client == nil {
        fmt.Println("initializing redis within rate limiter ... ")
        client = redis.NewClient(&redis.Options{
            Addr:     os.Getenv("REDIS_URI"),
            Password: os.Getenv("REDISCLI_AUTH"),
            DB:       0,
        })

        _, err := client.Ping(context.Background()).Result()
        if err != nil {
            return nil, fmt.Errorf("error initializing Redis client: %v", err)
        }
    }
    fmt.Println("Redis rate limiter initialized  ... ")
    return &RedisRateLimiter{client: client}, nil
}

func (rl *RedisRateLimiter) CheckRateLimit(r *http.Request) error {
    fmt.Println("Checking rate limit ... ")
    var rateLimiterKey string
    apiKey := os.Getenv("API_KEY") // only api key auth configured at this time
    if apiKey == "" {
        return fmt.Errorf("API key not configured")
    }

    defaultKeyPrefix := os.Getenv("DEFAULT_KEY_PREFIX")
    if defaultKeyPrefix == "" {
        return fmt.Errorf("DEFAULT_KEY_PREFIX environment variable not set")
    }

    authHeader := r.Header.Get("Authorization")
    if authHeader != "" {
        token, err := jwt.Parse(strings.TrimPrefix(authHeader, "Bearer "), func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })
        if err == nil && token.Valid {
            claims := token.Claims.(jwt.MapClaims)
            rateLimiterKey = fmt.Sprintf("%s:%v", defaultKeyPrefix, claims["key"])
        }
    }

    if rateLimiterKey == "" && r.Header.Get("X-API-Key") == apiKey {
        rateLimiterKey = fmt.Sprintf("%s:%v", defaultKeyPrefix, apiKey)
    }

    if rateLimiterKey == "" {
        return fmt.Errorf("Unauthorized")
    }

    rateLimit, windowSize := getRateLimitAndWindowSize()

    result, err := rl.client.Do(context.Background(), "FCALL", "sliding_window_counter_with_pubsub", 1, rateLimiterKey, rateLimit, windowSize).Result()
    if err != nil {
        fmt.Println("Error performing rate limiting")
        errMsg := fmt.Sprintf("Error performing rate limiting: %v", err)
        fmt.Println("Error:", errMsg)
        return fmt.Errorf(errMsg)
    }

    rateLimited, ok := result.(int64)
    if !ok {
        fmt.Println("the redis rate limiter response was not ok ...  ")
        return fmt.Errorf("Unexpected response type from rate limiter")
    }
    if rateLimited == 1 {
        fmt.Println("Uh oh! Rate limited ...  ")
        errMsg := "Rate limit exceeded"
        fmt.Println("Error:", errMsg)
        return fmt.Errorf(errMsg)
    }
    
    fmt.Println("Rate limit completed, returning nil ... ")
    return nil
}

func getRateLimitAndWindowSize() (int, int) {
    rateLimit := getEnvAsInt("RATE_LIMIT", 20)
    windowSize := getEnvAsInt("WINDOW_SIZE", 60)
    return rateLimit, windowSize
}

func getEnvAsInt(key string, defaultValue int) int {
    value := os.Getenv(key)
    if value != "" {
        if intValue, err := strconv.Atoi(value); err == nil {
            return intValue
        }
    }
    return defaultValue
}
