FROM python:3.9-slim

COPY ./requirements.txt /app/
RUN pip install -r /app/requirements.txt

COPY . /app/

CMD ["bash", "/app/app.sh"]
