FROM python:3-buster
LABEL maintainer="Ingo Keck <ingokeck@ingokeck.de>"

# Create the fs-repo directory and switch to a non-privileged user.
RUN mkdir /app
#RUN groupadd -r www-data && 
#RUN adduser -r -s /bin/false -g www-data www-data
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
RUN adduser --shell /bin/false --gecos '' --disabled-password --uid 1000 mspreader
RUN chown -R mspreader:mspreader /app
USER mspreader
CMD ["python3", "/app/reader_server.py"]
