FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 sentinel && mkdir -p /app/data && chown -R sentinel:sentinel /app/data
COPY --chown=sentinel:sentinel app ./app
COPY --chown=sentinel:sentinel web ./web
USER sentinel
EXPOSE 8787
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8787"]
