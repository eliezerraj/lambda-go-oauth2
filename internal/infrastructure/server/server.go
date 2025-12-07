package server

import(
	"context"
	"strings"
	
	"github.com/rs/zerolog"
	"github.com/aws/aws-lambda-go/events"

	"github.com/lambda-go-oauth2/shared/erro"
	"github.com/lambda-go-oauth2/internal/domain/model"
	"github.com/lambda-go-oauth2/internal/domain/service"

	go_core_otel_trace "github.com/eliezerraj/go-core/v2/otel/trace"
)

var tracerProvider go_core_otel_trace.TracerProvider
var response *events.APIGatewayProxyResponse
var policyData model.PolicyData

type Server struct {
	appServer *model.AppServer
	workerService *service.WorkerService	
	logger *zerolog.Logger
}

// About inicialize handler
func NewLambdaServer(appServer *model.AppServer,
					 workerService *service.WorkerService,
					 appLogger *zerolog.Logger) *Server {

	logger := appLogger.With().
						Str("package", "infrastructure.server").
						Logger()
	logger.Info().
			Str("func","NewLambdaServer").Send()

    return &Server{
		appServer: appServer,
		workerService: workerService,
		logger: &logger,
    }
}

// About handle the request
func (s *Server) LambdaHandlerRequest(ctx context.Context,
									  request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	s.logger.Info().
			 Str("func","LambdaHandlerRequest").Send()

	// get the resquest-id and put in inside the 
	ctx = context.WithValue(ctx, "trace-request-id", request.RequestContext.RequestID)

	// Set policy data
	policyData.Effect = "Deny"
	policyData.PrincipalID = "go-oauth-apigw-authorization-lambda"
	policyData.Message = "unauthorized"
	policyData.MethodArn = request.MethodArn

	//token structure
	bearerToken, err := s.tokenStructureValidation(ctx, request)
	if err != nil{
		switch err {
		case erro.ErrArnMalFormad:
			policyData.Message = "token validation - arn invalid"
		case erro.ErrBearTokenFormad:
			policyData.Message = "token validation - beared token invalid"
		default:
			policyData.Message = "token validation"
		}
		return s.workerService.GeneratePolicyFromClaims(ctx, policyData, nil), nil
	}

	var KeySign	interface{}
	if s.appServer.Application.AuthenticationModel == "RSA" {
		KeySign = s.appServer.RsaKey.RsaPublic
	} else {
		KeySign = s.appServer.RsaKey.HsaKey
	}

	// Check token signature
	claims, err := s.workerService.TokenSignedValidation(*bearerToken, KeySign, s.logger)
	if err != nil {
		s.logger.Error().
				 Err(err).
	             Msg("erro TokenSignedValidation")
		return s.workerService.GeneratePolicyFromClaims(ctx, policyData, claims), nil
	}

	// Scope ON
	if (true) {
		// Check scope
		if !s.workerService.ScopeValidation(ctx, *claims, policyData.MethodArn) {
			policyData.Message = "unauthorized by token validation"
			return s.workerService.GeneratePolicyFromClaims(ctx, policyData, claims), nil
		} 
	}

	policyData.Effect = "Allow"
	policyData.Message = "Authorized"

	return s.workerService.GeneratePolicyFromClaims(ctx, policyData, claims), nil	
}

// About check the token structure
func (s *Server) tokenStructureValidation(ctx context.Context, 
										  request events.APIGatewayCustomAuthorizerRequestTypeRequest) (*string, error){
	s.logger.Info().Str("func","tokenStructureValidation").Send()

	ctx, span := tracerProvider.SpanCtx(ctx, "adapter.lambdaHandler.tokenStructureValidation")
	defer span.End()
	
	//Check the size of arn
	if (len(request.MethodArn) < 6 || request.MethodArn == ""){
		s.logger.Error().
				  Str("request.MethodArn size error : ", string(rune(len(request.MethodArn)))).Send()
		return nil, erro.ErrArnMalFormad
	}

	//Parse the method and path
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	s.logger.Debug().
			 Interface("method : ", method).Msg("")
	s.logger.Debug().
	         Interface("path : ", path).Msg("")

	//Extract the token from header
	var token string
	if (request.Headers["Authorization"] != "")  {
		token = request.Headers["Authorization"]
	} else if (request.Headers["authorization"] != "") {
		token = request.Headers["authorization"]
	}

	// check format token
	var bearerToken string
	tokenSlice := strings.Split(token, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = token
	}

	// length
	if len(bearerToken) < 1 {
		s.logger.Error().
				Msg("empty token")
		return nil, erro.ErrBearTokenFormad
	}

	return &bearerToken, nil
}
