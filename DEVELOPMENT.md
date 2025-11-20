# Development Overview

## Component Relationships

The repository is split into a few cooperating parts: the ImGui desktop client (`pipetap-gui`), the injected hook + proxy DLL (`pipetap-dll`), shared contracts and logging (`pipetap-shared`), a Python SDK for the TCP-to-named-pipe proxy (`pipetap-python`), and two small fixtures to exercise the flow (`pipe-test-client`/`pipe-test-server`). The diagram shows how they depend on each other and where the DLL sits when injected into a target named-pipe server.

```mermaid
graph TD
    shared["pipetap-shared\n(IPC contracts, logging)"]
    gui["pipetap-gui\n(ImGui desktop client)"]
    dll["pipetap-dll\n(Injected hook + TCP proxy)"]
    py["pipetap-python\n(TCP SDK, PyPI)"]
    client["pipe-test-client\n(Named pipe fixture)"]
    server["pipe-test-server\n(Target fixture)"]

    shared --> gui
    shared --> dll
    gui -- inject/control --> dll
    gui -- control/events named pipes --> dll
    py -- TCP port 61337 --> dll
    client -- named pipe I/O --> server
    dll -- injected hooks --> server
```

## Protocol Flow

Once injected, the DLL stands between the real client/server named-pipe traffic and the GUI (and optionally the Python SDK). It establishes PID-scoped control/event pipes for coordination with the GUI, continues to forward intercepted I/O to the real APIs, and exposes a TCP listener for remote pipe access. The sequence below outlines the major message paths.

```mermaid
sequenceDiagram
    participant GUI as pipetap-gui
    participant DLL as pipetap-dll in target
    participant Server as Named Pipe Server (target)
    participant Client as Named Pipe Client
    participant Python as pipetap-python (optional)

    GUI->>DLL: Inject support DLL into target process
    DLL-->>GUI: Expose PID-scoped control/events pipes
    GUI-->>DLL: Connect and send control commands
    Client->>Server: Named pipe read/write calls
    DLL-->>GUI: Stream intercepted I/O events
    GUI-->>DLL: Optional edits/blocks then send replacements
    Python->>DLL: TCP connect (default 61337)
    Python->>DLL: Request remote pipe open/send/recv
    DLL->>Server: Relay proxied I/O to the pipe server
    DLL->>Client: Return pass-through or edited responses
```
