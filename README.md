# Trojan
## Trojan virus concept on local server for academic purposes, list of all possible attacks and short description of virus are below
The program operates in a client-server architecture (victim-attacker).
Communication is handled by raw socket interface.

### Server (attacker):
- Has graphical application  
- Supports multiple clients simultaneously (using asynchronous sockets or threads)  
- Has a functional and sensible GUI  

### Client (victim):
- Console application   
- Automatically connects to the server  
- Allows bidirectional communication with the server  

### Trojan funtionalities
- Clipboard content replacement under specific condition - bank account number – implemented with using hooks, message handling  
- Simple ping test
- Basic system info
- List of files in directory given by attacker
- Content of file given by attacker
