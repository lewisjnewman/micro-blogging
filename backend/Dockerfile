FROM golang:alpine

# Create a new top level app directory and switch to it
RUN mkdir -p /app
WORKDIR /app

# Copy the source code into the app directory, as well as the dot env
COPY ./src .

RUN go build -o backend-app

ENTRYPOINT [ "/app/backend-app" ]