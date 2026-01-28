# Example Python App

This is a basic Python application for development inside a Docker container. It prints a message and demonstrates connectivity to a Raspberry Pi via SSH (user: pi@192.168.178.66).

## Usage

- Build and run the app using Docker Compose:
  ```sh
  docker-compose up --build
  ```
- The app will print a hello message and attempt to connect to the Raspberry Pi via SSH.

## SSH Details
- Host: 192.168.178.66
- User: pi
- You may need to set up SSH keys or provide a password for the first connection.

## Development
- Edit `app/main.py` to modify the example app.
- Use the provided Dockerfile and docker-compose.yml for local development.
