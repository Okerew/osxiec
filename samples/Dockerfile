# Test Dockerfile for osxiec to Docker conversion

# Use a lightweight base image
FROM alpine:latest

# Set the working directory in the container
WORKDIR /app

# Copy the application files from the osxiec container
# Note: This will be handled by the conversion script, so we don't need COPY instructions here

# Install any needed packages
RUN apk add --no-cache python3 py3-pip

# Set environment variables (these will be overwritten by the conversion script if not using a custom Dockerfile)
ENV MEMORY_SOFT_LIMIT=256m
ENV MEMORY_HARD_LIMIT=512m
ENV CPU_PRIORITY=20

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Run a simple Python HTTP server when the container launches
CMD ["python3", "-m", "http.server", "8080"]
