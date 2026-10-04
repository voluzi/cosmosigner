FROM golang:1.26-alpine AS builder

ARG VERSION=dev
ARG COMMIT=none

RUN apk --no-cache add git make

WORKDIR /src/app/

COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg \
  VERSION=$VERSION COMMIT=$COMMIT make build

FROM golang:1.27.1-bookworm AS builder-pkcs11
ARG VERSION=dev
ARG COMMIT=none
WORKDIR /src/app/
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    VERSION=$VERSION COMMIT=$COMMIT make build-pkcs11

FROM gcr.io/distroless/cc-debian12:nonroot AS pkcs11
WORKDIR /
COPY --from=builder-pkcs11 /src/app/bin/cosmosigner-pkcs11 /bin/cosmosigner
USER 65532:65532
ENTRYPOINT ["cosmosigner"]
CMD ["start"]

FROM gcr.io/distroless/static AS default
WORKDIR /
COPY --from=builder /src/app/bin/cosmosigner /bin/
ENTRYPOINT ["cosmosigner"]
CMD ["start"]
