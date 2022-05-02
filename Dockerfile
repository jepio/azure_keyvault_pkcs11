ARG IMAGE=ubuntu:21.10
FROM ${IMAGE} AS development

RUN if [ "${IMAGE}" = "ubuntu:18.04" ]; then \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates gnupg software-properties-common wget lsb-release && \
  ( wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | apt-key add - ) && \
  apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main"; \
  fi
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y libcurl4-openssl-dev libssl-dev libxml2-dev git make gcc g++ cmake vim p11-kit libp11-kit-dev gnutls-bin ninja-build pkg-config
RUN git clone https://github.com/Azure/azure-sdk-for-cpp /tmp/sdk && \
  cmake -S /tmp/sdk -B /tmp/build -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON && \
  cmake --build /tmp/build -- -j8 -v && \
  cmake --install /tmp/build && \
  rm -rf /tmp/sdk /tmp/build
RUN git clone https://github.com/json-c/json-c -b json-c-0.16-20220414 --depth 1 /tmp/json-c && \
  cmake -S /tmp/json-c -B /tmp/build -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON && \
  cmake --build /tmp/build -- -j8 -v && \
  cmake --install /tmp/build && \
  rm -rf /tmp/json-c /tmp/build

FROM development AS final
COPY . /work
RUN cmake -S /work -B /build -GNinja -DCMAKE_BUILD_TYPE=Release && \
  cmake --build /build -- -j8 -v && \
  cmake --install /build && \
  rm -rf /work /build

FROM ${IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libcurl4
COPY --from=final /usr/local/lib/pkcs11 /usr/local/lib/pkcs11
