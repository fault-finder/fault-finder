FROM ubuntu:22.04

# Set environment variables to avoid user interaction during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary tools and libraries
# RUN apk update && apk add --no-cache openssh-client git cmake
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libjson-c-dev \
    libcapstone-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /root/.ssh/ && ssh-keyscan github.com >> /root/.ssh/known_hosts

# Download, build, and install Unicorn
RUN git clone --depth 1 --branch 2.1.1 https://github.com/unicorn-engine/unicorn.git && cd unicorn && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j 4 && \
    make install && ldconfig

#RUN ldconfig

# # Copy your C application source code to the container
COPY shared /usr/src/faultfinder/shared
COPY Makefile /usr/src/faultfinder/
COPY finder /usr/src/faultfinder/finder

WORKDIR /usr/src/faultfinder

RUN make

ENTRYPOINT ["./faultfinder"]
#ENTRYPOINT ["bash"]
