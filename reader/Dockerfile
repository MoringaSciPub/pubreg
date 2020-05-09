FROM python:3-buster
LABEL maintainer="Ingo Keck <ingokeck@ingokeck.de>"

# Create the fs-repo directory and switch to a non-privileged user.
RUN mkdir /app
#RUN groupadd -r www-data && 
#RUN adduser -r -s /bin/false -g www-data www-data
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
ENV USERID 1000
RUN adduser --shell /bin/false --gecos '' --disabled-password --uid $USERID mspreader
RUN chown -R mspreader:mspreader /app
RUN chmod u+w /app
USER mspreader
CMD ["python3", "/app/reader_server.py"]
