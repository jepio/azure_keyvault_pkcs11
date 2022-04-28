FROM ubuntu:21.10

RUN apt-get update && \
  apt-get install -y libcurl4-openssl-dev libssl-dev libxml2-dev git make gcc g++ cmake vim p11-kit libp11-kit-dev gnutls-bin ninja-build
RUN git clone https://github.com/Azure/azure-sdk-for-cpp /tmp/sdk && \
  cmake -S /tmp/sdk -B /tmp/build -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON && \
  cmake --build /tmp/build -- -j8 -v && \
  cmake --install /tmp/build && \
  rm -rf /tmp/sdk /tmp/build
