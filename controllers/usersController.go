package controllers

import (
	"fmt"
	"go_jwt_auth/initializers"
	"go_jwt_auth/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ----------
// * Sign Up
// ----------
func SignUp(ctx *gin.Context) {
	// Get the email/pass of request body
	var body struct {
		Email    string
		Password string
	}

	if ctx.Bind(&body) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to read body",
		})
		return
	}
	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to hash password",
		})
		return
	}

	// Create the user
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to create user",
		})
		return
	}

	// Respond
	ctx.JSON(http.StatusCreated, gin.H{
		"message": "user created",
	})
}

// -------
// * Login
// -------
func Login(ctx *gin.Context) {
	// Get email and pass off request body
	var body struct {
		Email    string
		Password string
	}

	if ctx.Bind(&body) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to read body",
		})
		return
	}

	// Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		ctx.JSON(http.StatusNotFound, gin.H{
			"message": "Invalid email or password",
		})
		return
	}

	// Compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		fmt.Println(err)

		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid email or password",
		})
		return
	}

	// Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 1).Unix(), // 1 hour
	})

	// Generate a refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 2).Unix(), // 2 hour
	})

	// Sign and get the complete encoded token as a string using the secret
	// for token
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to create token",
		})
		return
	}
	// for refresh
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to create refresh token",
		})
	}

	// new trend is to add jwt to cookie
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("Authorization", tokenString, 3600, "", "", false, false)
	ctx.SetCookie("Refresh", refreshTokenString, 7200, "", "", false, false)

	// send it back
	ctx.JSON(http.StatusOK, gin.H{
		"token":        tokenString,
		"refreshToken": refreshTokenString,
		"data":         user,
	})
}

// ---------------
// * Refresh Token
// ---------------
func RefreshToken(ctx *gin.Context) {
	// Get the refresh token

	// Get sub from token

	// Check if sub is valid

	// Generate token

	// Sign token

	// send it back
}

// ------------
// * Middleware
// ------------
func Validate(ctx *gin.Context) {
	user, _ := ctx.Get("user")
	// user.(models.User).Email

	ctx.JSON(http.StatusOK, gin.H{
		"message": "I'm logged in",
		"data":    user,
	})
}
