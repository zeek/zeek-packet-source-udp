FROM zeek/zeek-dev

RUN apt-get update && apt-get install --no-install-recommends -y \
	cmake \
	g++ \
	libpcap-dev \
	liburing-dev \
	make \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /zeek-packet-source-udp

COPY ./ .

RUN rm -rf build && mkdir ./build && cd build && CXXFLAGS='-Wall -pedantic -Werror' cmake ../ && VERBOSE=1 make
