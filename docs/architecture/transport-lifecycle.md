# Transport lifecycle and recovery

The host activates and selects a physical card before constructing a transport adapter.
The adapter reports exact framing and frame-size limits. It sends one physical reader frame
per `exchange` call and never reconnects or retries internally.

The protocol owner retains or borrows callback context according to the versioned transport
descriptor. A retained callback lease spans exchange, reset, cancellation, and state-change
notification, so close cannot release context while any callback is executing.

An external removal, reset, or reconnection advances the transport generation. Managed and
raw operations compare the generation before and after I/O and invalidate selection and
authentication when it changes.

Queued cancellation performs no I/O. Active cancellation calls the transport independently
of the operation lock and may race completion. Another exchange cannot begin until the
reader callback has returned or an explicit reset establishes a new generation.

Unknown mutation delivery is a durable application recovery state. Resetting or reopening a
reader does not prove that a debit, credit, write, or commit failed on the card.
