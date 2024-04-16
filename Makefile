# Output File Location
ROOT_DIR=$(shell git rev-parse --show-toplevel)
DIR=$(ROOT_DIR)/build
BINARY=aws-authorizer-lambda
TAG="1.0.5"

$(shell mkdir -p ${DIR})

build-lambda-linux-arm64:
	mkdir -p "${DIR}/linux"
	GOOS=linux GOARCH=arm64 go build -o "${DIR}/linux/${BINARY}" ${ROOT_DIR}/cmd/lambda

build-push-docker-image:
	docker buildx build --platform linux/arm64 -f "${ROOT_DIR}/Dockerfile" --tag dcodetech/aws-authorizer-lambda:${TAG} --push --provenance=false ${ROOT_DIR}

clean:
	rm -rf ${DIR}*
