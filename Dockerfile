FROM golang:1.19-alpine

WORKDIR /app
COPY . /app

RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go env

RUN go mod tidy -v
RUN go mod download

RUN go build -o /oss cmd/main.go

CMD [ "/oss" ]