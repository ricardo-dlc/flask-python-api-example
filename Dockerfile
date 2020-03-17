FROM python:3.8-alpine
ENV TZ=America/Cancun
RUN apk add -U tzdata && \
    cp /usr/share/zoneinfo/$TZ /etc/localtime && \
    apk add gcc g++ libffi-dev openssl openssl-dev python3-dev
ADD . /app
RUN chmod 777 /app/init_project.sh
WORKDIR /app/code
RUN pip install -r ../requirements.txt
CMD [ "/bin/sh", "../init_project.sh"]