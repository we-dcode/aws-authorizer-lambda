# Use the official Golang image as base image
FROM golang:1.22-alpine AS build

# Set the working directory inside the container
WORKDIR /app
RUN apk --no-cache add make git

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN make build-lambda-linux-arm64

FROM alpine:latest

WORKDIR /app
COPY --from=build /app/build/linux/aws-authorizer-lambda .

CMD ["./aws-authorizer-lambda"]