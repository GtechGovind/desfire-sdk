# Node and TypeScript

The package exposes strict TypeScript declarations and compiled ESM. Friendly managed and offline
APIs are exported from `@desfire/ev3`; `@desfire/ev3/raw` exports the expert RawChannel and
generated operation inventory.

Each Card owns one worker for blocking native calls. Reader and key-provider Promises execute
on the main event loop. Operation IDs and the canonical manifest hash are checked before open
so an older addon cannot silently dispatch a different function.

Queued aborts perform no native I/O. Active cancellation requests reader interruption. If a
timeout wins while the reader Promise is still pending, the Card enters a quiescing state and
rejects further exchanges until that Promise settles or reset establishes a new generation.

Binary inputs are snapshotted when admitted to the queue. Binding-owned key snapshots are
wiped after use; JavaScript-owned data remains the caller's responsibility.

Offline transaction-MAC calculation and verification require the caller's complete authoritative
TMI. The SDK does not construct EV3 TMI automatically.
