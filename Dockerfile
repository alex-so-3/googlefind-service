FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
# GoogleFindMyTools, pinned to the version this service was tested with
ARG GFMT_REF=d46e952
RUN git clone https://github.com/leonboe1/GoogleFindMyTools /gfmt && git -C /gfmt checkout $GFMT_REF
# frida is only used for tracker provisioning, the browser libs only for the (desktop) login
RUN grep -v -i frida /gfmt/requirements.txt > /tmp/req.txt \
    && pip install --no-cache-dir -r /tmp/req.txt fastapi "uvicorn[standard]"
# Tokens live in the volume
RUN ln -sf /data/secrets.json /gfmt/Auth/secrets.json
COPY service.py /srv/service.py
WORKDIR /srv
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8090"]
