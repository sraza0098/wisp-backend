FROM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /out/wisp

FROM gcr.io/distroless/base-debian12
ENV WISP_VERSION=0.0.1
COPY --from=build /out/wisp /wisp
EXPOSE 8080
CMD ["/wisp"]
