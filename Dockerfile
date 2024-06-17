FROM python:3.9-slim

WORKDIR /app

COPY .. .

RUN pip install --upgrade -r requirements.txt

EXPOSE 5000

CMD ["python", "main_app.py"]