# Base image: Azure Functions Python 3.11 runtime
FROM mcr.microsoft.com/azure-functions/python:4-python3.11

# Required Azure Functions env vars
ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    FUNCTIONS_WORKER_RUNTIME=python

# Install dependencies first (layer caching — only rebuilds when requirements change)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy function source code
COPY . /home/site/wwwroot
