# Kstructcollector

Collect kernel structures dividing them for kmalloc cache sizes

## Requirements

- pahole

## Note

Kstructcollector is a simple pahole output parser that can be helpful when doing UAF exploits or other operations which require info regarding how the kernel structs are allocated in kmalloc caches
