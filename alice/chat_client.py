#!/usr/bin/env python3

import socket, ssl, os, sys, select,queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

# This class implements the client side of secure_chat_app.
class Chat_Client:
    # The IP address, port and address family of the server given provided initialization.
    def __init__(self,ip_addr,port,addr_family):
        new_socket = socket.socket(addr_family,socket.SOCK_STREAM)
        new_socket.connect((ip_addr,port))
        # Pre-loading the trusted certificates and creating a trust store.
        self.trust_store = chat_utils.make_trust_store(['./rootCA.crt'])
        # Upon connection, the chat protocol is initiated.
        handshake_result = self.handle_chat_handshake(new_socket)
        # The above method returns either HANDSHAKE_FAILED, HANDSHAKE_SUCCESS_TLS or HANDSHAKE_SUCCESS_NO_TLS indicating the state of the chat_handshake.
        if handshake_result != chat_utils.HANDSHAKE_FAILED:
            print(Fore.CYAN + Style.BRIGHT + 'Connected to the server! Type "CHAT_CLOSE" to end the  connection. \n')
            # Setting the connection to non blocking, so that the user can send and recieve messages whenever.
            self.connection.setblocking(0)
            # The list of input streams present.
            self.inputs = [sys.stdin, self.connection]
            # The list of entities with pending outgoing messages.
            self.outputs = []
            # A message queue for the pending outgoing messages to the server.
            self.message_queue = Queue.Queue()
            # A list to contain the received fragments of a message untill all of its fragments have arrived.
            self.fragment_list = []
            # The number of messages sent so far.
            self.sent_message_number = 0
            # The number of messages received so far.
            self.recieved_message_number = 0
            self.lastline_type = 1
            # Now running a loop for as long as the connection between the server and client exists.
            while len(self.inputs) > 1:
                # Using the select library to filter the inputs and outputs list and obtain from them the entities that are ready for IO.
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
                # Iterating over all the entities that have pending messages to be read
                for s in readable:
                    # If the entity is the user input buffer, then the message read from it is to be sent to the server.
                    if s is sys.stdin:
                        input_msg = s.readline()
                        input_msg = input_msg[:-1]
                        if input_msg.strip() != '':
                            self.sent_message_number += 1
                            if self.lastline_type == 1:
                                self.lastline_type = 0
                            # The message thus read is enqueued into the message queue, implying that it has to be sent to the server.
                            self.message_queue.put(input_msg)
                            # Adding the server to the outputs list, implying that there are pending messages to be sent to the server.
                            if self.connection not in self.outputs:
                                self.outputs.append(self.connection)
                    # If the entity is the server, then there is an incoming message from the server to the client.
                    else:
                        try:
                            data = s.recv(4096).decode('UTF-8')
                            # If the message is CHAT_CLOSE, It means that the server intends to close the connection.
                            if data == chat_utils.CHAT_CLOSE:
                                print(Fore.RED + Style.BRIGHT + "\nServer ended the session! Closing the application!", Style.RESET_ALL+'\n')
                                self.close_connection()
                            else:
                                # If the message is a chat message, then it is passed to the handle_new_message function that takes care of handling the fragments of the message.
                                if data[:12] == chat_utils.CHAT_MESSAGE:
                                    self.handle_new_message(data)
                        except ssl.SSLWantReadError:
                            pass
                # Now iterating over the list of entities that have pending messages to be written to.
                for s in writable:
                    try:
                        next_msg = self.message_queue.get_nowait()
                    except Queue.Empty:
                        self.outputs.remove(s)
                    else:
                        # If the user types CHAT_CLOSE, it means that he intends to close the connection.
                        if next_msg == chat_utils.CHAT_CLOSE:
                            s.send(next_msg.encode('UTF-8'))
                            print(Fore.RED + Style.BRIGHT + '\nClosing the connection!',Style.RESET_ALL+'\n')
                            self.close_connection()
                        else:
                            # If the message is not CHAT_CLOSE, then in accordance with the protocol, the message is brokendown into fragments and sent to the server.
                            msg_blocks = chat_utils.fragment(next_msg, self.sent_message_number)
                            for msg in msg_blocks:
                                s.send(msg)
                # Iterating over the list of entities that have thrown an exception.
                for s in exceptional:
                    if s == self.connection:
                        self.close_connection()
                        if handshake_result == chat_utils.HANDSHAKE_SUCESS_TLS:
                            new_socket.close()
        else:
            print(Fore.RED + Style.BRIGHT + "Oops... something went wrong! Connection failed. \n")

    def get_TLS_context(self):
        # creates a SSL context with all the necessary information
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("./rootCA.crt")
        context.load_cert_chain(certfile="./alice.crt", keyfile="./alice.key")
        # This is to enforce the usage of TLS 1.3
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        return context

    # This function carries out the chat protocol initiation and completes the handshake.
    def handle_chat_handshake(self, socket):
        input_str = chat_utils.CHAT_HELLO
        socket.sendall(input_str.encode('UTF-8'))
        resp = socket.recv(4096).decode('UTF-8')
        if resp == chat_utils.CHAT_REPLY:
            input_str = chat_utils.CHAT_STARTTLS
            socket.sendall(input_str.encode('UTF-8'))
            resp = socket.recv(4096).decode('UTF-8')
            if resp == chat_utils.CHAT_STARTTLS_ACK:
                context = self.get_TLS_context()
                secureSocket = context.wrap_socket(socket)
                serverCert = secureSocket.getpeercert(binary_form=True)
                # verifying the validity and integrity of the server certificate against the trust store.
                if chat_utils.cert_checker(serverCert, self.trust_store)
                    input_str = chat_utils.CHAT_HANDSHAKE_COMPLETED
                    secureSocket.sendall(input_str.encode('UTF-8'))
                    # Secure connection successfully established using TLS 1.3.
                    return chat_utils.HANDSHAKE_SUCESS_TLS
                else:
                    input_str = chat_utils.CHAT_INVALID_CERTIFICATE
                    socket.sendall(input_str.encode('UTF-8'))
                    secureSocket.close()
                    socket.close()
            elif resp == chat_utils.CHAT_STARTTLS_NOT_SUPPORTED:
                self.connection = socket
                input_str = chat_utils.CHAT_HANDSHAKE_COMPLETED
                socket.sendall(input_str.encode('UTF-8'))
                # Plain text connection successfully established.
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            else:
                input_str = chat_utils.CHAT_INVALID_HANDSHAKE
                socket.sendall(input_str.encode('UTF-8'))
                socket.close()
        else:
            input_str = chat_utils.CHAT_INVALID_HANDSHAKE
            socket.sendall(input_str.encode('UTF-8'))
            socket.close()
        # Connection failed wither due to inconsistencies in the protocol or due to invalid certificate.
        return chat_utils.HANDSHAKE_FAILED

    # This function handles the messages received from the server.
    def handle_new_message(self,data):
        # First the details of the message like the message number, number of fragments and the fragment number are obtained.
        msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
        # if the message number is not equal to the number of messages received yet, it implies that this is a new message.
        if self.recieved_message_number != msg_num:
            self.recieved_message_number = msg_num
            # If the new message has only one fragment, then we just print it.
            if num_fragments == 1:
                if self.lastline_type == 1:
                    print("\033[A                             \033[A")
                else:
                    print("")
                    self.lastline_type = 1
                print(Fore.MAGENTA + Style.BRIGHT + "Bob says: ",Fore.GREEN + Style.BRIGHT + data[28:], Fore.CYAN + Style.BRIGHT +'\n')
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
                print(Fore.MAGENTA + Style.BRIGHT + "Bob says: ",Fore.GREEN + Style.BRIGHT + recieved_msg, Fore.CYAN + Style.BRIGHT +'\n')
                self.fragment_list.clear()
            # If the received fragment is not the last fragment, then we simply append it into the fragment list.
            else:
                self.fragment_list.append(data)

    # This is a handy function to help with the closing of the connection.
    def close_connection(self):
        if self.connection in self.outputs:
            self.outputs.remove(self.connection)
        self.inputs.remove(self.connection)
        self.connection.close()
        del self.message_queue

def main():
    arg_len = len(sys.argv)
    if arg_len < 2:
        print("\nusage: \t -c <host>")
    else:
        if sys.argv[1] == '-c':
            if arg_len == 2:
                print("\nusage: \n \t -c <host> for clients, \n \t -s for server.")
            else:
                domain_name = sys.argv[2]
                # Obtaining the server ip address from the domain name.
                addr_info = socket.getaddrinfo(domain_name,8000)
                addr_family = socket.AF_INET
                # checking if the ip address belongs to the IPv4 or IPv6 family.
                if len(addr_info[0][4]) == 4:
                    addr_family = socket.AF_INET6
                ip_addr = addr_info[0][4][0]
                Chat_Client(ip_addr,8000,addr_family)
        else:
            print("\nusage: \n \t -c <host>")

main()