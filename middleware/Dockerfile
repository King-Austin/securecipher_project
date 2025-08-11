FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get upgrade -y && apt-get clean
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python manage.py collectstatic --noinput
CMD ["gunicorn", "securecipher.wsgi:application", "--bind", "0.0.0.0:8001", "--workers", "3"]
