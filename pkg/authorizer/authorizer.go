package authorizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/imroc/req/v3"
	"net/url"
	"strings"
	"time"
)

type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

//type JSONWebKeys struct {
//	Keys []struct {
//		Alg string `json:"alg"`
//		E   string `json:"e"`
//		Kid string `json:"kid"`
//		Kty string `json:"kty"`
//		N   string `json:"n"`
//		Use string `json:"use"`
//	} `json:"keys"`
//}

// Authorizer represents an authorizer object
type Authorizer struct {
	OidcDiscovery *OIDCDiscovery
	//JWKSKeys      *JSONWebKeys
	KeyFunc  keyfunc.Keyfunc
	Audience string
}

func NewAuthorizerWithAudience(oidcDiscoveryURL string, audience string) (*Authorizer, error) {

	oidcDiscovery, err := Discovery(oidcDiscoveryURL)
	if err != nil {
		return nil, err
	}

	keyFunc, err := GetKeyFunc(oidcDiscovery)
	if err != nil {
		return nil, err
	}

	return &Authorizer{
		OidcDiscovery: oidcDiscovery,
		KeyFunc:       keyFunc,
		Audience:      audience,
	}, nil
}

func NewAuthorizer(oidcDiscoveryURL string) (*Authorizer, error) {

	return NewAuthorizerWithAudience(oidcDiscoveryURL, "")
}

func Discovery(oidcDiscoveryURL string) (*OIDCDiscovery, error) {
	// Append the well-known path to the discovery URL
	discoveryURL, err := url.Parse(oidcDiscoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse discovery URL: %v", err)
	}
	discoveryURL.Path += "/.well-known/openid-configuration"

	// Perform HTTP request to retrieve OIDC configuration
	resp, err := req.Get(discoveryURL.String())

	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %v", err)
	}
	defer resp.Response.Body.Close()

	// Check response status code
	if resp.Response.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected response status: %v", resp.Response.Status)
	}

	// Decode the response body into OIDCDiscovery struct
	var config OIDCDiscovery
	if err := json.NewDecoder(resp.Response.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC configuration: %v", err)
	}

	return &config, nil
}

func GetKeyFunc(oidcDiscovery *OIDCDiscovery) (k keyfunc.Keyfunc, err error) {

	k, err = keyfunc.NewDefault([]string{oidcDiscovery.JWKSURI})
	return
}

func (a *Authorizer) ParseAndVerifyToken(tokenString string) (jwt.MapClaims, error) {

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, a.KeyFunc.Keyfunc)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	// Validate token claims
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("fail to pars token.Claims to jwt.MapClaims")
	}

	// Validate issuer
	if issuer, ok := claims["iss"].(string); !ok || issuer != a.OidcDiscovery.Issuer {
		return nil, fmt.Errorf("invalid issuer. received: '%s' while expected: '%s'", issuer, a.OidcDiscovery.Issuer)
	}

	if a.Audience != "" {
		// Validate audience
		if aud, ok := claims["aud"].(string); !ok || aud != a.Audience {
			return nil, fmt.Errorf("invalid audience. received: '%s' while expected: '%s'", aud, a.Audience)
		}
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, fmt.Errorf("token expired. received: '%f'", exp)
		}
	} else {
		return nil, fmt.Errorf("invalid expiration - fail to parse to float64")
	}

	return claims, nil
}
