FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    iproute2 iptables procps net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ../../app/pi_agent /app/pi_agent

EXPOSE 8787
ENV AGENT_PORT=8787
CMD ["python", "-m", "pi_agent.agent"]
