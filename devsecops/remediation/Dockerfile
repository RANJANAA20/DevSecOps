FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd --system --no-create-home appuser
USER appuser
EXPOSE 5000
ENV APP_HOST=0.0.0.0
CMD ["python", "app.py"]
