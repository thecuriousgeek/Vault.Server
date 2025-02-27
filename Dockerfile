FROM python:alpine
ENV PYTHONUNBUFFERED 1
RUN pip3 install --no-cache-dir pycryptodome flask[async] python-dateutil
RUN mkdir /src
COPY *.py /src
ADD LibPython /src/LibPython
WORKDIR /src
EXPOSE 80
VOLUME ["/data"]
CMD python Program.py
