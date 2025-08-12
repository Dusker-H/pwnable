FROM ubuntu@sha256:965fbcae990b0467ed5657caceaec165018ef44a4d2d46c7cdea80a9dff0d1ea
ENV DEBIAN_FRONTEND=noninteractive \
    LC_CTYPE=C.UTF-8

RUN apt-get update
RUN apt-get install -y xinetd

COPY prob.xinetd.d /etc/xinetd.d/prob
RUN echo "prob 1004/tcp" >> /etc/services

RUN useradd yisf -m -s /bin/sh

RUN chmod -R 700 /bin
RUN chmod -R 700 /sbin
RUN chmod -R 700 /usr/bin
RUN chmod -R 700 /usr/sbin
RUN chmod 755 /bin
RUN chmod 755 /sbin
RUN chmod 755 /usr/bin
RUN chmod 755 /usr/sbin
RUN chmod 755 /bin/ls
RUN chmod 755 /bin/cat
RUN chmod 755 /bin/sh
RUN chmod 755 /bin/dash
RUN chmod 755 /bin/bash
RUN chmod 600 /etc/passwd
RUN chmod 600 /etc/passwd-
RUN chmod 600 /etc/group
RUN chmod 600 /etc/group-
RUN chmod 600 /etc/shadow
RUN chmod 600 /etc/shadow-
RUN chmod -R 700 /var/log
RUN chmod -R 700 /var/tmp
RUN chmod 700 /var
RUN chmod 700 /tmp
RUN chmod 600 /dev/shm

RUN mkdir -p /chroot/bin /chroot/lib /chroot/lib64 /chroot/usr /chroot/sbin /chroot/etc /chroot/dev /chroot/proc /chroot/sys /chroot/home/yisf

COPY flag /chroot/home/yisf/
COPY flag /chroot/
COPY prob /chroot/home/yisf/

RUN cp /bin/sh /chroot/bin/ && cp /bin/cat /chroot/bin/ && cp /bin/ls /chroot/bin/

RUN cp -r /lib/x86_64-linux-gnu /chroot/lib/
RUN cp -r /lib64/ld-linux-x86-64.so.2 /chroot/lib64

RUN chown -R yisf:yisf /chroot/home/yisf
RUN chown yisf:yisf /chroot/flag

RUN chmod 500 /chroot/home/yisf/
RUN chmod 400 /chroot/home/yisf/flag
RUN chmod 400 /chroot/flag
RUN chmod 500 /chroot/home/yisf/prob

CMD ["/usr/sbin/xinetd", "-dontfork"]