package main

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  uint
}

func main() {
	// DB
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// input
	var input string = "Mona"

	// Binary Expr
	var query string = "SELECT * FROM users WHERE name = '" + input + "'"
	db.Raw(query).Scan(&User{})

	// Format String
	var query2 string = fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", input)
	db.Raw(query2).Scan(&User{})
}
