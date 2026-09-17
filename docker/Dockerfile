# gdb-mcp debugging image for the docker launcher backend.
#
# Build from the repo root:
#   docker build -f docker/Dockerfile -t gdb-mcp:latest .
#
# The server then launches gdb inside ephemeral containers:
#   GDB_MCP_LAUNCHER=docker gdb-mcp
# (containers run with --cap-add=SYS_PTRACE and a relaxed seccomp profile;
# the session's cwd and the in-gdb plugin are bind-mounted per launch).
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb python3 python3-pip python3-venv gcc git ca-certificates \
        socat tmux \
    && rm -rf /var/lib/apt/lists/*

# pwndbg (project setup.sh installs its own python deps into a venv)
RUN git clone --depth=1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg && ./setup.sh

RUN python3 -m pip install --no-cache-dir --break-system-packages pwntools

COPY gdb_mcp_plugin.py /opt/gdb-mcp/gdb_mcp_plugin.py
COPY src /opt/gdb-mcp/src
COPY pyproject.toml README.md /opt/gdb-mcp/
RUN python3 -m pip install --no-cache-dir --break-system-packages /opt/gdb-mcp

# gdb picks pwndbg up via gdbinit so hello.pwndbg is true for heap tools
RUN echo "source /opt/pwndbg/gdbinit.py" >> /root/.gdbinit

WORKDIR /root
CMD ["bash"]
