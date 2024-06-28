# Use the official Python 3 image based on Alpine Linux
# Reference: https://hub.docker.com/_/python
FROM python:3-alpine3.18

# Create a non-root user for improved security
RUN addgroup --gid 10001 --system veeder \
 && adduser --uid 10000 --system --ingroup veeder --home /home/veeder veeder

# Set the working directory inside the container
WORKDIR /honeyscanner/honeyscanner

# Create a log directory and set permissions
RUN mkdir -p /honeyscanner/honeyscanner/logs \
    && chown -R root:root /honeyscanner/honeyscanner

# Expose the port on which GasPot will listen
EXPOSE 10001

# Copy the application files, including the config.ini.dist file, to the container
COPY config.ini.dist /honeyscanner/honeyscanner/config.ini
COPY GasPot.py /honeyscanner/honeyscanner/GasPot.py


# Define the entry point for the container
ENTRYPOINT ["nohup", "python3", "GasPot.py"]

# Add a health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD nc -z localhost 10001
