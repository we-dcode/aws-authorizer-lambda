package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/we-dcode/aws-authorizer-lambda/pkg/authorizer"
	"os"
)

var DenyPermission = func(requestMethodArn string) events.APIGatewayCustomAuthorizerResponse {
	return events.APIGatewayCustomAuthorizerResponse{
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Deny",
					Resource: []string{requestMethodArn},
				},
			},
		},
	}
}

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {

	if request.Type != "TOKEN" {
		return DenyPermission(request.MethodArn), fmt.Errorf("authorization lambda support TOKEN request type but received '%s'", request.Type)
	}

	token := request.AuthorizationToken
	if token == "" {
		return DenyPermission(request.MethodArn), fmt.Errorf("unauthorized: Missing Authorization Token")
	}

	identityServer := os.Getenv("IDENTITY_SERVER_URL")
	if identityServer == "" {
		return DenyPermission(request.MethodArn), fmt.Errorf("IDENTITY_SERVER_URL not set")
	}

	audience := os.Getenv("AUDIENCE")

	a, err := authorizer.NewAuthorizerWithAudience(identityServer, audience)
	if err != nil {
		return DenyPermission(request.MethodArn), err
	}

	claims, err := a.ParseAndVerifyToken(token)
	if err != nil {
		return DenyPermission(request.MethodArn), err
	}

	authResponse := events.APIGatewayCustomAuthorizerResponse{
		PrincipalID: fmt.Sprintf("%v", claims["sub"]),
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   "Allow",
					Resource: []string{request.MethodArn},
				},
			},
		},
		Context: claims,
	}

	return authResponse, nil
}
