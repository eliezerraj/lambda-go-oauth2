package main

import(
	"fmt"
	"os"
	"io"
	"context"

	"github.com/rs/zerolog"
	//"github.com/aws/aws-lambda-go/lambda" //enable this line for run in AWS
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/lambda-go-oauth2/shared/log"
	"github.com/lambda-go-oauth2/shared/certificate"
	"github.com/lambda-go-oauth2/internal/domain/service"
	"github.com/lambda-go-oauth2/internal/domain/model"
	"github.com/lambda-go-oauth2/internal/infrastructure/config"
	"github.com/lambda-go-oauth2/internal/infrastructure/server"	

	go_core_otel_trace 	 "github.com/eliezerraj/go-core/v2/otel/trace"
	go_core_aws_s3 "github.com/eliezerraj/go-core/v2/aws/s3"

	// traces
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
	//"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda" //enable this line for run in AWS
	// ---------------------------  use it for a mock local ---------------------------
	"encoding/json"  
	"github.com/aws/aws-lambda-go/events" 
	// ---------------------------  use it for a mock local ---------------------------	
)

// Global variables
var ( 
	appLogger 	zerolog.Logger
	logger		zerolog.Logger
	appServer	model.AppServer

	appInfoTrace 		go_core_otel_trace.InfoTrace
	appTracerProvider 	go_core_otel_trace.TracerProvider
	sdkTracerProvider 	*sdktrace.TracerProvider
)

// About init
func init(){
	// Load application info
	application := config.GetApplicationInfo()
	awsService 	:= config.GetAwsServiceEnv()

	appServer.Application = &application
	appServer.AwsService = &awsService

	// Log setup	
	writers := []io.Writer{os.Stdout}

	if	application.StdOutLogGroup {
		file, err := os.OpenFile(application.LogGroup, 
								os.O_APPEND|os.O_CREATE|os.O_WRONLY, 
								0644)
		if err != nil {
			panic(fmt.Sprintf("Failed to open log file: %v", err))
		}
		writers = append(writers, file)
	} 
	multiWriter := io.MultiWriter(writers...)

	// log level
	switch application.LogLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn": 
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error": 
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// prepare log
	appLogger = zerolog.New(multiWriter).
						With().
						Timestamp().
						Str("component", application.Name).
						Logger().
						Hook(log.TraceHook{}) // hook the app shared log

	// set a logger
	logger = appLogger.With().
						Str("package", "main").
						Logger()
		
	// load configs					
	otelTrace 	:= config.GetOtelEnv()
	appServer.EnvTrace = &otelTrace	
}

// About main
func main (){
	logger.Info().
			Msgf("STARTING APP version: %s",appServer.Application.Version)
	logger.Info().
			Interface("appServer", appServer).Send()
			
	// create context and otel log provider
	ctx, cancel := context.WithCancel(context.Background())

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(appServer.AwsService.AwsRegion))
	if err != nil {
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	if appServer.Application.OtelTraces {
		// Otel over aws services
		otelaws.AppendMiddlewares(&awsCfg.APIOptions)

		appInfoTrace.Name = appServer.Application.Name
		appInfoTrace.Version = appServer.Application.Version
		appInfoTrace.ServiceType = "lambda-workload"
		appInfoTrace.Env = appServer.Application.Env
		appInfoTrace.Account = appServer.Application.Account

		sdkTracerProvider = appTracerProvider.NewTracerProvider(ctx, 
																*appServer.EnvTrace, 
																appInfoTrace,
																&appLogger)

		otel.SetTextMapPropagator(
    		propagation.NewCompositeTextMapPropagator(
				propagation.TraceContext{}, 
				propagation.Baggage{},
    		),
		)

		otel.SetTracerProvider(sdkTracerProvider)
		sdkTracerProvider.Tracer(appServer.Application.Name)
	}

	// Load application keys
	bucketS3, err := go_core_aws_s3.NewAwsBucketS3(	&awsCfg,
										      		&appLogger)
	if err != nil {
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load the private key
	rsaKey := model.RsaKey{}
	privateKey, err := bucketS3.GetObject( ctx, 
											appServer.AwsService.BucketNameRSAKey,
											appServer.AwsService.FilePathRSA,
											appServer.AwsService.FileNameRSAPrivKey )
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	rsaPrivate, err := certificate.ParsePemToRSAPriv(privateKey,
													 &appLogger)
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load the private key
	publicKey, err := bucketS3.GetObject( ctx, 
											appServer.AwsService.BucketNameRSAKey,
											appServer.AwsService.FilePathRSA,
											appServer.AwsService.FileNameRSAPubKey )
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	rsaPublic, err := certificate.ParsePemToRSAPub(publicKey,
												   &appLogger)
	if err != nil{
		logger.Fatal().
			   Err(err).Send()
		os.Exit(3)
	}

	// Load everything in rsa key model
	rsaKey.HsaKey 		= "SECRET-12345" // for simplicity 
	rsaKey.RsaPublic 	= rsaPublic
	rsaKey.RsaPrivate 	= rsaPrivate
	rsaKey.RsaPrivatePem = string(*privateKey)
	rsaKey.RsaPublicPem = string(*publicKey)
	appServer.RsaKey 	= &rsaKey	

	// Wire 
	workerService := service.NewWorkerService(&appServer,
											  &appLogger)
	
	// Cancel everything
	defer func() {
		// cancel log provider
		if sdkTracerProvider != nil {
			err := sdkTracerProvider.Shutdown(ctx)
			if err != nil{
				logger.Error().
				       Ctx(ctx).
					   Err(err). 
					   Msg("Erro to shutdown tracer provider")
			}
		}
		
		// cancel context
		cancel()

		logger.Info().
			   Ctx(ctx).
			   Msgf("App %s Finalized SUCCESSFULL !!!", appServer.Application.Name)
	}()

	// Create Lambda Server										   
	lambdaServer := server.NewLambdaServer(&appServer,
											workerService,
	 									    &appLogger)

	// ----------------------------------------------------------------------	
	/*mockEvent := events.APIGatewayCustomAuthorizerRequestTypeRequest{
		Type:       "TOKEN",
		MethodArn:  "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info",
		Headers: map[string]string{
			"Authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJnby1vYXV0aCIsInZlcnNpb24iOiIzIiwiand0X2lkIjoiYWVjMWNkMDgtOGQ2YS00OTMzLThiNTctZjZjZDI5NTA1ODJiIiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTc0MTc1OTk1M30.TY6TSKY1Xr-IdIaN6yEcQFTG6zHXBgxQj8XGcDBu4jLI0bK20cCzmvCEi40sVof52RTc5i5fXSeFqRC17Ua7jdVY-DW9iT17nacjHeJl4d1A3pVGM1bTVRttRe2_klSB7hgvKyesCUKbHbUqJW_7iZY_ld_0BW7Vr6v7sINcZfrg-lWWV2xqI8wIRUAZERA8MzIykVIDkJoM4Ee6YRICDVGXsKCMMxjOhSPIqxV20K6ew-4wgRoeB5SvQiCa2_Oi3TuC1mcm6lqHPHpqyjf6rpIctiE9kfAQXISnO7_5-fe4Ptyrx3KdN4Vyq5w5cSPBL7jHbzk27KKSO3FiyEVFfHKGBfUPCC24xxWDaMJcyw1t_WRyKal4FvWrlsIPsF9lhxrJzOCk1mwNkJ3XWHaWI-6gk_EIOvk0r1syFjeEWGlTTQpiyxl0EI0231shCDlGsDzzNjKDaBdEZ4IK3lGEclPGKk0Ss1TjK3ntRdfQtIq2HCYzq4hGslAf2hzQSYyS7vNwnM6uZojg6k6oaIlGszeRsbwfXaLCPdMBfif6h3K0aEPfv6EMYOae933P3NvcAPCCLREOzeblo7dv-mayQdmOzf7bZfuCDvH_e04TWEcDOGznGnlhOk_DvJCDaa0DNF9iG3EFoA7cye8IGtxHiFci-XejSavscZ2WrAZg7LE",
		},
	}*/
	
	mockEvent := events.APIGatewayCustomAuthorizerRequestTypeRequest{
		Type:       "TOKEN",
		MethodArn:  "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info",
		RequestContext: events.APIGatewayCustomAuthorizerRequestTypeRequestContext{
			RequestID: "request-id-12345",
		},
		Headers: map[string]string{
			"Authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJnby1vYXV0aC1sYW1iZGEiLCJ2ZXJzaW9uIjoiMi4yIiwiand0X2lkIjoiNjcwN2JlZTYtZjBlZi00OTQ4LTllMjAtMWFkMGZhYzc3NDc0IiwidXNlcm5hbWUiOiJ1c2VyLTAzIiwidGllciI6InRpZXItMDMiLCJhcGlfYWNjZXNzX2tleSI6IkFQSV9BQ0NFU1NfS0VZX1VTRVJfMDMiLCJzY29wZSI6WyJ0ZXN0LnJlYWQiLCJ0ZXN0LndyaXRlIiwiYWRtaW4iXSwiZXhwIjoxNzY1NTAxOTAxfQ.k6bisWp9AytELB9bQ73oJh6vnlURUt4FS0n8F4IZpzvQetH_KdYlq-6ONV0NLrUzId8PJLTjm0rJ25CzT5BLl1JGyXNRRvrbjZknqYB313gs9LQpIhZjgFnjJ_9XASEiBYGN_zH6Ql8e9Kzzk_HDTOpVY_yKpjlc1qz1rZ3pmr-FvafdbyP4QpHftu1vIbrPTfW3ucHvqg1liwRS1C7lyfgMQyOZRScZ9xs7WnB835HHDrfwUhblHbCYntqi3sZgrtn9oO0CRmAtmlux2feeuPzS7zdJtPuOh3NBp79aVy9ojfgijDj7fdY-0nsejy-r9DAZfuHT5dg7ZlqX-PUqrGOHT8qUt6xJOs5idey_I_N15ZZKcI6AgyjxeIN6yIDuDozO-VSm7m-bMtsT1ilSKiMJYaUVU6CACl2QvHxBUrn6OSKL8GTNco8hkPH31Hi63AWPVuqPuGQK-iJw3Q2jSpz8KfCdJqLMpHZocjXGuULNXLmZTdh8-GGWo1SOyfJCLWhrdbu5f02SmXsliX0QZQzozklKcvEsucv6-WzvDvnA2F_4pY9afRK3bX2QWxTGoK4guAOq7gU8U-S8zUbsYIYCec_-aDOrGi3XsPaWGf_LixBn3tL8AkDmxExbf1TN2yJgT3Nh__UkKL5QHa4vCibvVgHkWgipNu3TrPvb4d0",
		},
	}

	res, err := lambdaServer.LambdaHandlerRequest(ctx, 
									 			 mockEvent)
	if err != nil {
		logger.Error().
			   Err(err).Send()
	}else {
		s, _ := json.MarshalIndent(res, "", "\t")
		fmt.Println(string(s))
	}
	// ----------------------------------------------------------------------	

	// Start handler
	//lambda.Start(otellambda.InstrumentHandler(lambdaServer.LambdaHandlerRequest),)
}