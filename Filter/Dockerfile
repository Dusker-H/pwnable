FROM python:3.13@sha256:385ccb8304f6330738a6d9e6fa0bd7608e006da7e15bc52b33b0398e1ba4a15b

ENV user=filter

RUN apt-get update
RUN apt-get install socat iputils-ping -y

RUN useradd -d /home/$user $user

ADD chall.py /home/$user/chall.py
ADD flag /home/$user/flag

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/chall.py
RUN chown root:$user /home/$user/flag

RUN chmod 755 /home/$user/chall.py
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 chall.py,nofork,stderr"]