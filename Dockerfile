FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY policies ./policies
COPY examples ./examples
RUN go vet ./... && go test ./... && \
    CGO_ENABLED=0 go build -o /playground ./cmd/playground

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /playground /playground
EXPOSE 8080
ENV PLAYGROUND_ADDR=:8080
ENTRYPOINT ["/playground"]
