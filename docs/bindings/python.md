# Python

Python 3.10 and later exposes a synchronous context-managed `Card` and an `AsyncCard` backed
by one dedicated worker thread per card. Reader callbacks remain application-owned and must
not retry or reconnect during an exchange.

Public dataclasses, enums, and protocols represent identifiers, settings, results, transport,
errors, and key sources. `desfire_ev3.raw` is generated from the canonical ABI manifest and
preserves C names and exact integer widths for expert integrations.

Key providers may be synchronous or asynchronous. Resolution occurs inside the card FIFO
before native I/O. The binding wipes its temporary native key copy; callers remain responsible
for Python-owned objects that the interpreter or operating system may copy.

An unknown mutation raises `DesfireError` with `requires_reconciliation=True` and is never
retried by a convenience method.
