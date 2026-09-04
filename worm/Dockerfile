FROM python:3.12-slim
LABEL org.wormbench.role=worm
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py tools.py advisories.json attack_graph.json ./
COPY payload/ /opt/worm-payload/
CMD ["python3", "-u", "agent.py"]
