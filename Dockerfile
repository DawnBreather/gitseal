# gitseal broker — distroless, static, nonroot. Multi-stage.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off → fully static; trim + strip for a small image.
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/sealdbroker ./cmd/sealdbroker

# Distroless nonroot: no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sealdbroker /sealdbroker
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/sealdbroker"]
