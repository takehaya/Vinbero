package vinberov1

// ReasonNotFound starts the reason of a per-target OperationError when the
// target does not exist: an interface name that resolves to nothing, or no
// entry on it. A caller doing teardown can treat it as already gone.
const ReasonNotFound = "not found"
