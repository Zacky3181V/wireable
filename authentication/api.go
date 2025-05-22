package authentication

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Zacky3181V/wireable/vaultclient"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func generateJWT(username string, jwtSecret []byte) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

var jwtSecret string

// @Summary Login
// @Description Authenticates the user and returns a JWT token.
// @ID login
// @Accept json
// @Produce json
// @Param loginRequest body Credentials true "Login credentials"
// @Success 200
// @Router /authentication/login [post]
func LoginHandler(c *gin.Context) {
	var creds Credentials

	vc := vaultclient.GetClient()

	jwtSecret = vaultclient.ProcessSecret(vc, "secret", "wireable/jwt", "jwtsecret")
	username := vaultclient.ProcessSecret(vc, "secret", "wireable/credentials", "username")
	password := vaultclient.ProcessSecret(vc, "secret", "wireable/credentials", "password")

	fmt.Println(jwtSecret, username, password)

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if creds.Username != username || creds.Password != password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := generateJWT(creds.Username, []byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("username", claims["username"])

		c.Next()
	}
}
