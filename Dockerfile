FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/wisp

FROM gcr.io/distroless/base-debian12
ENV WISP_VERSION=0.0.1
COPY --from=build /out/wisp /wisp
EXPOSE 8080
CMD ["/wisp"]
