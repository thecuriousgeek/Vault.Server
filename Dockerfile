FROM python:alpine
ENV PYTHONUNBUFFERED 1
RUN mkdir /src
COPY . /src
WORKDIR /src
RUN pip3 install -r ./requirements.txt
EXPOSE 80
VOLUME ["/Vault"]
CMD python Program.py /Vault
