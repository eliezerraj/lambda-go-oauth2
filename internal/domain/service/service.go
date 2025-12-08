package service

import (
	"fmt"
	"context"
	"strings"

	"github.com/rs/zerolog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/aws/aws-lambda-go/events"

	"github.com/lambda-go-oauth2/shared/erro"
	"github.com/lambda-go-oauth2/internal/domain/model"

	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"
)

var tracerProvider go_core_otel_trace.TracerProvider

type WorkerService struct {
	appServer *model.AppServer
	logger 	  *zerolog.Logger

	TokenSignedValidation func(string, 
							   interface{},
							   *zerolog.Logger) (*model.JwtData, error)
}

// ------------------------- RSA ------------------------------/
// About check token RSA expired/signature and claims
func tokenValidationRSA(bearerToken string, 
						rsaPubKey interface{},
						logger *zerolog.Logger)( *model.JwtData, error){
	logger.Info().
			Str("func","tokenValidationRSA").Send()

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, 
								  claims, func(token *jwt.Token) (interface{}, error) {
		return rsaPubKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}

// -------------------------------H 256 ---------------
// About check token HS256 expired/signature and claims
func tokenValidationHS256(bearerToken string, 
						  hs256Key interface{},
						  logger *zerolog.Logger) ( *model.JwtData, error){

	logger.Info().
			Str("func","TokenValidationHS256").Send()

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(fmt.Sprint(hs256Key)), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}
// ------------------------- Support ------------------------------/
// About new worker service
func NewWorkerService(appServer *model.AppServer,
					  appLogger *zerolog.Logger) *WorkerService{

	logger := appLogger.With().
						Str("package", "domain.service").
						Logger()
	logger.Info().
			Str("func","NewWorkerService").Send()

	var tokenSignedValidation func(string, interface{}, *zerolog.Logger) (*model.JwtData, error)

	if appServer.Application.AuthenticationModel == "RSA" {
		tokenSignedValidation = tokenValidationRSA
	} else {
		tokenSignedValidation = tokenValidationHS256
	}

	return &WorkerService{
		appServer: appServer,
		logger: &logger,
		TokenSignedValidation: tokenSignedValidation,
	}
}

// About Generate Policy
func(w *WorkerService) GeneratePolicyFromClaims(ctx context.Context, 
												policyData model.PolicyData,
												claims *model.JwtData) (events.APIGatewayCustomAuthorizerResponse){
	w.logger.Info().
			 Str("func","GeneratePolicyFromClaims").Send()
	
	// trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.GeneratePolicyFromClaims")
	defer span.End()

	// Setup the policy
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: policyData.PrincipalID}
	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   policyData.Effect,
				Resource: []string{policyData.MethodArn},
			},
		},
	}

	// InsertDataAuthorizationContext
	authResponse.Context = make(map[string]interface{})
	authResponse.Context["authMessage"] = policyData.Message
	authResponse.Context["tenant_id"] = "NO-TENANT"

	if claims != nil {
		// check insert jwt-id
		if claims.JwtId != "" {
			authResponse.Context["jwt_id"] = claims.JwtId
		}
		// if the ApiAccessKey is informed used it
		if claims.ApiAccessKey != "" {
			authResponse.UsageIdentifierKey = claims.ApiAccessKey
		} else {
			// Insert a default
			w.logger.Warn().
			 		Str("func","GeneratePolicyFromClaims").
					Msg("API_KEY for usage plan NOT INFORMED, ingested the DEFAULT !!!")
			authResponse.UsageIdentifierKey = "API_ACCESS_KEY_DEFAULT_001"
		}
	}
	w.logger.Info().
			 Interface("authResponse", authResponse).Send()

	return authResponse
}

// About insert session data
func(w *WorkerService) ScopeValidation (ctx context.Context, claims model.JwtData, arn string) bool{
	w.logger.Info().
			Str("func","ScopeValidation").Send()
	
	// trace
	ctx, span := tracerProvider.SpanCtx(ctx, "service.ScopeValidation")
	defer span.End()

	// valid the arn
	res_arn := strings.SplitN(arn, "/", 4)
	method := res_arn[2]
	path := res_arn[3]

		// Valid the scope in a naive way
	var pathScope, methodScope string
	for _, scopeListItem := range claims.Scope {
		// Split ex: versiom.read in 2 parts
		scopeSlice := strings.Split(scopeListItem, ".")
		pathScope = scopeSlice[0]
		
		// In this case when just method informed it means the all methods are allowed (ANY)
		// Ex: path (info) or (admin)
		// if lenght is 1, means only the path was given
		if len(scopeSlice) == 1 {
			if pathScope == "admin" {
				w.logger.Debug().
						 Msg("++++++++++ TRUE ADMIN ++++++++++++++++++")
				return true
			}
			// if the path is equal scope, ex: info (informed) is equal info (scope)
			if strings.Contains(path, scopeSlice[0]) {
				w.logger.Debug().
						 Msg("++++++++++ NO ADMIN BUT SCOPE ANY ++++++++++++++++++")
				return true
			}
		// both was given path + method
		} else {
			// In this case it would check the method and the scope(path)
			// Ex: path/scope (version.read)
			w.logger.Debug().
					 Interface("scopeListItem....", scopeListItem).Msg("")

			methodScope = scopeSlice[1]

			if pathScope == path {
				w.logger.Debug().
				         Msg("PASS - Paths equals !!!")
				if method == "ANY" {
					w.logger.Debug().
					          Msg("ALLOWED - method ANY!!!")
					return true
				} else if 	(method == "GET" && methodScope == "read" ) || 
							(method == "POST" && methodScope == "write" ) ||
							(method == "PUT" && methodScope == "write") ||
							(method == "PATCH" && methodScope == "update") ||
							(method == "DELETE" && methodScope == "delete"){
							w.logger.Debug().
							         Msg("ALLOWED - Methods equals !!!")
					return true
				} 
			}
		}
	}

	return false
}
