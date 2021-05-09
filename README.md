# ASSIGNMENT 3: Secure Chat using OpenSSL and MITM attacks
Created by: Group 10
- Anurag Reddy Karri, MA18BTECH11001
- Dheekshitha Bheemanath, CS18BTECH11006
- Abhignya Pampati, MA18BTECH11005

# Files included:

## Alice:
* Makefile
* chat_client.py
* chat_utils.py
* alice.crt
* alice.key
* alice.csr
* rootCA.crt

## Bob:
* Makefile
* chat_server.py
* chat_utils.py
* bob.crt
* bob.key
* bob.csr
* rootCA.crt

## Trudy:
* Makefile
* secure_chat_interceptor.py
* downgrade.py
* active_mitm.py
* chat_utils.py
* fakealice.crt
* fakealice.key
* fakealice.csr
* fakebob.crt
* fakebob.key
* fakebob.csr
* rootCA.crt
* rootCA.key

# Instructions to setup and execute:
* Place all the relevent files in the same folder and execute the command ***"make"***.
* The command "make" generates the corresponding executables, i.e, secure_chat_app for Alice and Bob, secure_chat_interceptor for Trudy.
* To execute the secure_chat_app in server mode, run ***"./secure_chat_app -s"***
* To execute the secure_chat_app in client mode, run ***"./secure_chat_app -c <server-name>"***
* In order to launch MITM attacks, execute the command ***"bash ~/poison-dns-alice1-bob1.sh"*** in the VM, to poison the DNS.
* To execute the secure_chat_interceptor in Downgrade attack mode, run ***"./secure_chat_interceptor -d <client-name> <server-name>"***
* To execute the secure_chat_interceptor in Active MITM attack mode, run ***"./secure_chat_interceptor -m <client-name> <server-name>"***
