FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt update && apt upgrade -y
RUN apt install -y curl build-essential software-properties-common clang 
RUN add-apt-repository ppa:ondrej/php
RUN apt update
RUN apt install -y php8.0 php8.0-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
