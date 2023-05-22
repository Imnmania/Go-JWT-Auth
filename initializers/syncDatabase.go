package initializers

import "go_jwt_auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
