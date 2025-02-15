# Create a Dockerfile
echo 'FROM python:3.8
WORKDIR /app
COPY . .
RUN pip install flask==2.0.0
EXPOSE 5000
CMD ["python", "app.py"]' > Dockerfile
