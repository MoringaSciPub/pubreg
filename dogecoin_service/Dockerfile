# we start with the download of the excecutable
FROM debian:bullseye-slim as build

RUN apt-get update && apt-get install -y \
    wget

WORKDIR /app

#RUN wget https://github.com/dogecoin/dogecoin/releases/download/v1.10.0-dogeparty/dogecoin-1.10.0-linux64.tar.gz
#RUN wget https://github.com/dogecoin/dogecoin/releases/download/v1.14.0/dogecoin-1.14.2-x86_64-linux-gnu.tar.gz
RUN wget https://github.com/dogecoin/dogecoin/releases/download/v1.14.6/dogecoin-1.14.6-x86_64-linux-gnu.tar.gz
#RUN tar xfv dogecoin-1.10.0-linux64.tar.gz
#RUN ls dogecoin-1.10.0/bin/
RUN tar xfv dogecoin-1.14.6-x86_64-linux-gnu.tar.gz
RUN ls dogecoin-1.14.6/bin/
#RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# now we make the actual image with the excecutable

FROM debian:bullseye-slim

COPY --from=build /app/dogecoin-1.14.6/bin/* /usr/local/bin/
COPY --from=build /app/dogecoin-1.14.6/lib/* /usr/local/lib/
#COPY --from=build /app/dogecoin-1.10.0/share/* /usr/local/share/

ADD dogecoin.conf /config/dogecoin.conf


# add a path top the dogecoin-directory
ENV DOGECOIN_PATH /data/dogecoin
RUN mkdir -p ${DOGECOIN_PATH}
# add it as volume
VOLUME /data/dogecoin


# Swarm TCP; should be exposed to the public
EXPOSE 22556
# Daemon RPC; must not be exposed publicly but to client services under you control
# EXPOSE 22555
ENV USERID 1000
RUN adduser --shell /bin/false --gecos '' --disabled-password --uid $USERID dogecoind
RUN chown -R dogecoind:dogecoind /data/dogecoin
RUN chown -R dogecoind /config

ENTRYPOINT ["/usr/local/bin/dogecoind", "-datadir=/data/dogecoin", "-conf=/config/dogecoin.conf", "-server"]
#ENTRYPOINT ["/usr/local/bin/dogecoind", "-datadir=/data/dogecoin", "-conf=/config/dogecoin.conf", "-server", "-testnet"]
