#!/usr/bin/env python3

import select, socket, sys, ssl, queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

# This class implements the server side of secure_chat_app.
class Chat_Server:
    # The IP address, port and address family of the server given provided initialization.
    def __init__(self,ip_addr,port,addr_family):
        # Now we estalish the server listening on port 8000
        self.server = socket.socket(addr_family, socket.SOCK_STREAM)
        self.server.bind((ip_addr, port))
        # Server is waiting for Client to connect
        self.server.listen(5)
        # Pre-loading the trusted certificates and creating a trust store.
        self.trust_store = chat_utils.make_trust_store(['./rootCA.crt'])
        print(Fore.GREEN + Style.BRIGHT + 'Server up and running! Waiting for client...\n')

        # The list of input streams present.
        self.inputs = [sys.stdin]
        # The list of entities with pending outgoing messages.
        self.outputs = []
        # A message queue for the pending outgoing messages to the server.
        self.message_queues = {}
        # A list to contain the received fragments of a message untill all of its fragments have arrived.
        self.fragment_list = []
        # The number of messages sent so far.
        self.sent_message_number = 0
        # The number of messages received so far.
        self.recieved_message_number = 0
        self.lastline_type = 1

        # We obtain the Socket and ip of the connected client
        connection, client_address = self.server.accept()
        # Setting the connection to non blocking, so that the user can send and recieve messages whenever.
        self.server.setblocking(0)
        # Upon setting up the connection, the chat protocol is initiated.
        handshake_result = self.handle_new_connection(connection)

        # The above method returns either HANDSHAKE_FAILED, HANDSHAKE_SUCCESS_TLS or HANDSHAKE_SUCCESS_NO_TLS indicating the state of the chat_handshake.
        if handshake_result != chat_utils.HANDSHAKE_FAILED:
            print(Fore.CYAN + Style.BRIGHT + 'Connection accepted from client! Type "CHAT_CLOSE" to end the connection. \n')
        else:
            print(Fore.RED + Style.BRIGHT + "Handshake failed! Rejecting connection.",Style.RESET_ALL+'\n')
        # Now running a loop for as long as the connection between the server and client exists.
        while len(self.inputs) > 1:
            # Using the select library to filter the inputs and outputs list and obtain from them the entities that are ready for IO.  
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            # Iterating over all the entities that have pending messages to be read
            for s in readable:
                # If the entity is the user input buffer, then the message read from it is to be sent to the client.
                if s is sys.stdin:
                    input_msg = s.readline()
                    input_msg = input_msg[:-1]
                    if input_msg.strip() != "":
                        if self.lastline_type == 1:
                            self.lastline_type = 0
                        self.sent_message_number += 1
                        # The message thus read is enqueued into the message queue, implying that it has to be sent to the client.
                        self.message_queues[self.client].put(input_msg)
                        # Adding the client to the outputs list, implying that there are pending messages to be sent to the client.
                        if self.client not in self.outputs:
                            self.outputs.append(self.client)
                # If the entity is the client, then there is an incoming message from the client to the server.
                else:
                    data = s.recv(4096).decode('UTF-8')
                    if data != chat_utils.CHAT_CLOSE:
                        # If the message is a chat message, then it is passed to the handle_new_message function that takes care of handling the fragments of the message.
                        if data[:12] == chat_utils.CHAT_MESSAGE:
                            self.handle_new_message(data)
                    # If the message is CHAT_CLOSE, It means that the client intends to close the connection.
                    else:
                        print(Fore.RED + Style.BRIGHT + "\nClient ended the session!", Style.RESET_ALL+'\n')
                        self.close_client_connection(s)
                        break
            # Now iterating over the list of entities that have pending messages to be written to.
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
                except Queue.Empty:
                    self.outputs.remove(s)
                else:
                    # If the user types CHAT_CLOSE, it means that he intends to close the connection.
                    if next_msg == chat_utils.CHAT_CLOSE:
                        s.send(next_msg.encode('UTF-8'))
                        print(Fore.RED + Style.BRIGHT + '\nClosing the connection!', Style.RESET_ALL+'\n')
                        self.close_client_connection(s)
                        break
                    else:
                        # If the message is not CHAT_CLOSE, then in accordance with the protocol, the message is brokendown into fragments and sent to the client.
                        msg_blocks = chat_utils.fragment(next_msg, self.sent_message_number)
                        for msg in msg_blocks:
                            s.send(msg)
            # Iterating over the list of entities that have thrown an exception.
            for s in exceptional:
                if s == self.client:
                    self.close_client_connection(s)
                    if handshake_result == chat_utils.HANDSHAKE_SUCESS_TLS:
                        connection.close()

    # This function carries out the chat protocol initiation and completes the handshake.
    def handle_new_connection(self, connection):
        incoming_msg = connection.recv(4096).decode('UTF-8')
        # If the received message is CHAT_HELLO, the server sends out a CHAT_REPLY packet
        if incoming_msg == chat_utils.CHAT_HELLO:
            response_msg = chat_utils.CHAT_REPLY
            connection.sendall(response_msg.encode('UTF-8'))
            incoming_msg = connection.recv(4096).decode('UTF-8')
            # If the next received message is CHAT_STARTTLS, the server sends out an acknowledgment
            if incoming_msg == chat_utils.CHAT_STARTTLS:
                response_msg = chat_utils.CHAT_STARTTLS_ACK
                connection.sendall(response_msg.encode('UTF-8'))
                secureClientSocket = ssl.wrap_socket(connection, 
                        server_side=True, 
                        ca_certs="./rootCA.crt", 
                        certfile="./bob.crt",
                        keyfile="./bob.key", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
                clientCert = secureClientSocket.getpeercert(binary_form=True)
                # If the client's certificate turns out to be valid
                if chat_utils.cert_checker(clientCert, self.trust_store):
                    incoming_msg = secureClientSocket.recv(4096).decode('UTF-8')
                    if incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                        self.inputs.append(secureClientSocket)
                        self.message_queues[secureClientSocket] = Queue.Queue()
                        self.client = secureClientSocket
                        return chat_utils.HANDSHAKE_SUCESS_TLS
                    else:
                        response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
                        connection.sendall(response_msg.encode('UTF-8'))
                        secureClientSocket.close()
                        connection.close()
                # If the client's certificate turns out to be invalid
                else:
                    response_msg = chat_utils.CHAT_INVALID_CERTIFICATE
                    connection.sendall(response_msg.encode('UTF-8'))
                    secureClientSocket.close()
                    connection.close()
            # If the received message is CHAT_HANDSHAKE_COMPLETED i.e. the client skipped CHAT_STARTTLS, server establishes a NO_TLS session
            elif incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                self.inputs.append(connection)
                self.message_queues[connection] = Queue.Queue()
                self.client = connection 
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            # If a packet different from the pre-established CHAT_PROTOCOL messages is sent, server takes it to be an invalid handshake
            else:
                response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
                connection.sendall(response_msg.encode('UTF-8'))
                connection.close()
        # If a packet different from the pre-established CHAT_PROTOCOL messages is sent, server takes it to be an invalid handshake
        else:
            response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
            connection.sendall(response_msg.encode('UTF-8'))
            connection.close()
        # Connection failed wither due to inconsistencies in the protocol or due to invalid certificate.
        return chat_utils.HANDSHAKE_FAILED

    # This function handles the messages received from the client.
    def handle_new_message(self, data):
        # First the details of the message like the message number, number of fragments and the fragment number are obtained.
        msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
        if self.recieved_message_number != msg_num:
            self.recieved_message_number = msg_num
            # If the new message has only one fragment, then we just print it.
            if num_fragments == 1:
                if self.lastline_type == 1:
                    print("\033[A                             \033[A")
                else:
                    print("")
                    self.lastline_type = 1
                print(Fore.MAGENTA + Style.BRIGHT  +"Alice says: ", Fore.GREEN + Style.BRIGHT + data[28:], Fore.CYAN + Style.BRIGHT + '\n')
            # If it has more than one fragment then we append it into the fragment list.
            else:
                self.fragment_list.append(data)
        # If the message received is not an entirely new message but a fragment of a message,
        else:
            # If the fragment received is indeed the last fragment, then we can parse all the received fragments, reconstruct the message and display it.
            if num_fragments == fragment_num:
                self.fragment_list.append(data)
                recieved_msg = chat_utils.parse(self.fragment_list)
                if self.lastline_type == 1:
                    print("\033[A                             \033[A")
                else:
                    print("")
                    self.lastline_type = 1
                print(Fore.MAGENTA + Style.BRIGHT +'Alice says: ', Fore.GREEN + Style.BRIGHT + recieved_msg, Fore.CYAN + Style.BRIGHT + '\n')
                self.fragment_list.clear()
            # If the received fragment is not the last fragment, then we simply append it into the fragment list.
            else:
                self.fragment_list.append(data)

    # This is a handy function to help with the closing of the connection with a client.
    def close_client_connection(self, client):
        if client in self.outputs:
            self.outputs.remove(client)
        self.inputs.remove(client)
        client.close()
        del self.message_queues[client]
        self.server.close()

def main():
    arg_len = len(sys.argv)
    if arg_len < 2:
        print("\nusage: \n \t -s")
    else:
        if sys.argv[1] == '-s':
            Chat_Server('172.31.0.3', 8000, socket.AF_INET)
        else:
            print("\nusage: \t -s")

main()