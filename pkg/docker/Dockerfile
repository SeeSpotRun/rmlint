# Rmlint
# VERSION 0.0.1
# Website: https://github.com/sahib/rmlint

FROM gliderlabs/alpine:3.1
MAINTAINER Christopher Pahl <sahib@online.de>
ENV PATH /rmlint:$PATH

RUN apk-install build-base python
RUN apk-install git scons glib glib-dev
RUN apk-install libelf libelf-dev
RUN apk-install sqlite-libs json-glib-dev

RUN git clone -b develop https://github.com/sahib/rmlint.git
WORKDIR rmlint
RUN scons config 
RUN HAVE_MM_CRC32_U64=0 scons DEBUG=1 -j4  # For releases you can omit DEBUG=1
CMD ["/bin/sh"]
