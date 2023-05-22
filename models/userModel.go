package models

import "time"

type User struct {
	// gorm.Model `json:"-"`
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Email     string    `gorm:"unique" json:"email"`
	Password  string    `json:"-"`
}
