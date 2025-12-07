# lambda-go-oauth2

    lambda-go-oauth2

## Manually compile the function

    New Version
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap ./cmd/main.go
    zip main.zip bootstrap collector.yaml

    Check file
    unzip -l main.zip

    aws lambda update-function-code \
        --region us-east-2 \
        --function-name lambda-go-oauth2 \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/lambda-go-oauth2/main.zip \
        --publish
