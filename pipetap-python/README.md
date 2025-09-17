# pipetap-python

This is a Python client to connect to a remote pipetap support DLL. The DLL exposes a TCP to Named Pipe proxy which allows you to interact with named pipes from the target process the support DLL lives in.

## installation

With pip:

```bash
pip install pipetap
```

## usage

```python
from pipetap import PipeTap

tap = PipeTap()
tap.connect("pipetap.test", "10.0.0.1")

tap.send("foo\n")
print(tap.recv())
```
