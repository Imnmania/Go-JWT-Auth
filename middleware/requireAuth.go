package middleware

import (
	"fmt"
	"go_jwt_auth/initializers"
	"go_jwt_auth/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(ctx *gin.Context) {
	fmt.Println("In middleware")

	// Get the cookie off req
	tokenString, err := ctx.Cookie("Authorization")
	fmt.Println("Token from Cookie => ", tokenString)
	if err != nil {
		tokenString = ctx.GetHeader("Authorization")
		fmt.Println("Token from Header => ", tokenString)

		if tokenString == "" {
			unauthorizedMessageWithStatus(ctx, "Token not found")
			return
		}
	}

	// Decode/validate
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Println("Error occured while parsing")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		fmt.Println("Error occured while parsing")
		// ctx.AbortWithStatus(http.StatusUnauthorized)
		unauthorizedMessageWithStatus(ctx, "Invalid token")
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["sub"], claims["exp"])

		// Check the exp
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			fmt.Println("Error while checking expiration")
			// ctx.AbortWithStatus(http.StatusUnauthorized)
			unauthorizedMessageWithStatus(ctx, "Token expired")
			return
		}

		// Find the user with token sub
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			fmt.Println("Error while finding the user")
			// ctx.AbortWithStatus(http.StatusUnauthorized)
			unauthorizedMessageWithStatus(ctx, "User does not exist!")
			return
		}

		// Attach to request
		ctx.Set("user", user)

		// continue
		ctx.Next()
	} else {
		// ctx.AbortWithStatus(http.StatusUnauthorized)
		unauthorizedMessageWithStatus(ctx, nil)
		return
	}
}

func unauthorizedMessageWithStatus(ctx *gin.Context, message any) {
	if message == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
		ctx.Abort()
	}
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"message": message,
	})
	ctx.Abort()
}
