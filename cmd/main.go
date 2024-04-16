package main

import (
	"fmt"
	"github.com/we-dcode/aws-authorizer-lambda/pkg/authorizer"
)

func main() {
	// Initialize your Lambda function here
	// For demonstration purposes, let's call the Authorizer method
	auth, err := authorizer.NewAuthorizer("https://cognito-idp.il-central-1.amazonaws.com/il-central-1_5SjnRdPZM")
	if err != nil {
		fmt.Printf("Error creating authorizer: %v\n", err)
		return
	}

	claims, err := auth.ParseAndVerifyToken("")
	if err != nil {
		fmt.Printf("Error validating token: %v\n", err)
		return
	}
	fmt.Println("Token claims:", claims)
}
