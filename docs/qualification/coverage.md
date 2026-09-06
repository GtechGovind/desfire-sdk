# Coverage rules

The machine-readable command matrix is `spec/ev3-command-coverage.yaml`. A row is
implemented only when the documented layout has a checked core operation, a managed
operation, and independent success and failure fixtures. An arbitrary raw exchange is useful
for integration but is not typed command support.

Binding parity is generated from `api/ev3-api.json`. A language package is complete only
when every operation intended for that surface is exported and its representative ownership,
error, cancellation, and result mapping fixtures pass.

Unsupported entries remain visible with their reason. They are not represented by empty
classes, permissive byte builders, or documentation that implies working support.
