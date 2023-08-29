package main

import (
	handle "2fatvalidate/api/handler"
	"2fatvalidate/api/utils"
	"fmt"
)

func main() {

	user := utils.User{
		Name: "name",
		Auth: "permission",
	}
	handle.ValidatePermission(user)

	fmt.Println("VALIDATE MFA RUNNING WITH THE PORT:8080")
}
