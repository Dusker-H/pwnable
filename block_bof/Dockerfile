FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update
RUN apt-get install -y socat

COPY ./deploy/flag /flag
COPY ./deploy/block_bof /block_bof

RUN chmod 755 /flag /block_bof

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:/prob

