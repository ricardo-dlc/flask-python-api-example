FROM python:3.8-alpine
ENV TZ=America/Cancun
RUN apk add -U tzdata && \
    cp /usr/share/zoneinfo/$TZ /etc/localtime && \
    apk add gcc g++ libffi-dev openssl-dev python3-dev
EXPOSE 5000
ADD . /app
WORKDIR /app/code
RUN pip install -r ../requirements.txt
CMD [ "python", "app2.py"]