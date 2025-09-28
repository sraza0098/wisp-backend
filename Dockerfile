# ---------- Build ----------
FROM golang:1.25 AS build
WORKDIR /src

# Enable Go build cache across layers
ENV CGO_ENABLED=0 \
    GOOS=linux

# First only deps for better caching
COPY go.mod go.sum ./
RUN go mod download

# Now copy the rest
COPY . .

# Optional: keep module graph tidy (safe)
RUN go mod tidy

# Build the binary from cmd/wisp
# TIP: use -trimpath to avoid leaking paths
RUN go build -trimpath -o /out/wisp ./cmd/wisp

# ---------- Runtime ----------
FROM gcr.io/distroless/base-debian12
# You can pass this at build time: --build-arg WISP_VERSION=0.1.4
ARG WISP_VERSION=0.0.1
ENV WISP_VERSION=${WISP_VERSION}

# App listens on PORT (defaults to 8080 in your code), expose 8080 here
EXPOSE 8080

# Copy binary
COPY --from=build /out/wisp /wisp

# Run
CMD ["/wisp"]
