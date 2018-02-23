FROM python:2.7-alpine

# Include following if proxies are needed:
#ENV http_proxy 'http://url'
#ENV https_proxy 'https://url'
#ENV HTTP_PROXY 'http://url'
#ENV HTTPS_PROXY 'https://url'

RUN apk update
RUN apk add gcc g++ make libffi-dev openssl-dev

EXPOSE 1336

RUN python -m pip install pyserial pyyaml pycrypto

WORKDIR /atm
ADD atm_backend ./atm_backend
RUN rm -rf -- /atm/atm_backend/logs
RUN mkdir /atm/atm_backend/logs
ADD setup.py ./setup.py
ADD README.md ./README.md
RUN python setup.py install

CMD python -m atm_backend.__main__
