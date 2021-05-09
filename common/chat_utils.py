from OpenSSL import crypto

# Packet headers used in the CHAT PROTOCOL
CHAT_HELLO = 'CHAT_HELLO'
CHAT_REPLY = 'CHAT_REPLY'
CHAT_STARTTLS = 'CHAT_STARTTLS'
CHAT_STARTTLS_ACK = 'CHAT_STARTTLS_ACK'
CHAT_STARTTLS_NOT_SUPPORTED = 'CHAT_STARTTLS_NOT_SUPPORTED'
CHAT_HANDSHAKE_COMPLETED = 'CHAT_HANDSHAKE_COMPLETED'
CHAT_INVALID_HANDSHAKE = 'CHAT_INVALID_HANDSHAKE'
CHAT_INVALID_CERTIFICATE = 'CHAT_INVALID_CERTIFICATE'
CHAT_MESSAGE = 'CHAT_MESSAGE'
CHAT_CLOSE = 'CHAT_CLOSE'

HANDSHAKE_FAILED = 'HANDSHAKE_ABORT'
HANDSHAKE_SUCESS_TLS = 'HANDSHAKE_SUCESS_TLS'
HANDSHAKE_SUCESS_NO_TLS = 'HANDSHAKE_SUCESS_NO_TLS'

# This is a handy function to fragment a message and add the CHAT_MESSAGE headers to each fragment
# The header consists of three pieces: the MESSAGE NUMBER, NUMBER OF FRAGMENTS of that particular message and current FRAGMENT'S NUMBER  
def fragment(message, message_num):
  messsage_size = 4068
  split = [message[i:i+messsage_size] for i in range(0, len(message), messsage_size)]
  prefix = 'CHAT_MESSAGE,' + format(message_num, '04d') + ',' + format(len(split), '04d') + ','
  fragment_numbers = [i for i in range(1, len(split)+1, 1)]
  split_message = [(prefix + format(y, '04d') + ',' + z).encode('UTF-8') for y,z in zip(fragment_numbers,split)]
  return split_message

# This is a handy function to reconstruct a message from all fragments received 
def parse(split_message):
  messages = [split_message[i][28:] for i in range(len(split_message))]
  message = ''.join(messages)
  return message

# This is a handy function to get the message details from its header: the MESSAGE NUMBER, NUMBER OF FRAGMENTS of that particular message and current FRAGMENT'S NUMBER  
def get_message_details(message):
  return int(message[13:17]), int(message[18:22]), int(message[23:27])

# This is a handy function to preload the rootCA certificate 
def make_trust_store(trusted_cert_paths):
  cert_store = crypto.X509Store()
  for trusted_cert_path in trusted_cert_paths:
    trusted_cert = open(trusted_cert_path,'rt').read()
    cert_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert))
  return cert_store

# This is a handy function to check the validity of the certificate chain  
def cert_checker(certificate, trust_store):
  try:
    cert_context = crypto.X509StoreContext(trust_store, crypto.load_certificate(crypto.FILETYPE_ASN1, certificate))
    cert_context.verify_certificate()
    return True
  except Exception as exc:
    print(exc)
    return False
  
