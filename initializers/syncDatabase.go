package initializers

import "jwt_auth_go/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
