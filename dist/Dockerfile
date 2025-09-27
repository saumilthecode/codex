FROM ubuntu
WORKDIR /tisc

RUN apt-get update && apt-get install -y socat

COPY csit_iot.bin .
COPY ext-flash.bin .
COPY stm32-emulator .
COPY stm32f407.svd .
COPY config.yaml .

ENTRYPOINT socat tcp-l:8000,fork,reuseaddr exec:"timeout 60s ./stm32-emulator config.yaml"
