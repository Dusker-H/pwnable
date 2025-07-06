FROM ubuntu:18.04@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

RUN apt-get update
RUN apt-get install -y gcc socat

RUN adduser gshs

ADD ./flag /home/gshs/flag
ADD ./chall /home/gshs/chall

RUN chown -R root:root /home/gshs
RUN chown root:gshs /home/gshs/flag
RUN chown root:gshs /home/gshs/chall

RUN chmod 755 /home/gshs/chall
RUN chmod 440 /home/gshs/flag

WORKDIR /home/gshs
USER gshs
EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:./chall,nofork,stderr"]