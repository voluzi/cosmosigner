FROM golang:1.26-alpine AS builder

ARG VERSION
ARG COMMIT

RUN apk --no-cache add git make

WORKDIR /src/app/

COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg \
  VERSION=$VERSION COMMIT=$COMMIT make build

FROM gcr.io/distroless/static
WORKDIR /
COPY --from=builder /src/app/bin/cosmosigner /bin/
ENTRYPOINT ["cosmosigner"]
CMD ["start"]
