# lambda-go-oauth2

   This is workload for POC purpose such as load stress test, gitaction, etc.

   The main purpose is to be an authorizer, checking the JWT signature/expiration and scope (naive method)

   There are 2 methods of JWT signature
   RSA (private key)
   HSA (symetric key)

## Integration

   This is workload requires a dynamo table (for the user data and scopes ) and a S3 bucket (private/public key)

## Enviroments

   For local test, create a AWS credentials and run the make file

    make

## Manually compile the function and update it (without run a ci/cd)

Compile

    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap ./cmd/main.go
    zip main.zip bootstrap collector.yaml

Check file

    unzip -l main.zip

Update function

    aws lambda update-function-code \
        --region us-east-2 \
        --function-name lambda-go-oauth2 \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-oauth2/main.zip \
        --publish
