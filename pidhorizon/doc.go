/*
Package pidhorizon provides discovering the PIDs/TIDs as used by the Linux
kernel (that is, in the root PID namespace) for processes and tasks in a child
PID namespace. Please note that this doesn't give your user space access to
these processes even if you happen to know their PIDs/TIDs in the root PID
namespace if you don't have access to the root PID namespace.
*/
package pidhorizon
