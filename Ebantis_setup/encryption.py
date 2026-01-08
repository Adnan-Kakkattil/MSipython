import json
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv
import os 

# Load the environment variables from the .env file
load_dotenv()

# Fetch secret key and ensure its length is valid
secret_key = "NlN57G7OEBZRvSaL"#os.getenv("SECRET_KEY").strip()  # Strip any surrounding spaces or newlines
xor_key ='PZH83QL' #os.getenv("XOR_KEY").strip()  # Strip any surrounding spaces or newlines
# Function to decrypt the response
def decrypt_response(obfuscated_encrypted_data, secret_key=secret_key):
    try:

        # Step 1: Reverse the obfuscation process
        decrypted_obfuscated_data = deobfuscate(obfuscated_encrypted_data)
        
        # Step 2: Initialize AES decryption with the secret key
        aes = AES_ENCRYPTION(secret_key)
        
        # Step 3: Decrypt the AES-encrypted data
        decrypted_data = aes.decrypt_string(decrypted_obfuscated_data)
        
        # Step 4: Return the decrypted data (which is a JSON string)
        return json.loads(decrypted_data)
    
    except Exception as e:
        print("error occured: ",e)


# Obfuscation and AES classes as before (for context)

def deobfuscate(obfuscated_data, shift=5, xor_key=xor_key):
    # Base64 decode the obfuscated string
    decoded_data = base64.b64decode(obfuscated_data).decode('utf-8')
    
    # Reverse XOR with the secondary key
    xor_reversed = ''.join(chr(ord(c) ^ ord(xor_key[i % len(xor_key)])) for i, c in enumerate(decoded_data))
    
    # Reverse the character shifting by shifting backwards
    reversed_shifted = ''.join(chr((ord(c) - shift) % 256) for c in xor_reversed)
    
    return reversed_shifted

class AES_ENCRYPTION:
    def __init__(self, key) -> None:
        self.key = key.encode('utf-8')
        self.iv = self.key  # Use the same key as the IV (Initialization Vector)
    
    def decrypt_string(self, encrypted_data):
        
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = base64.b64decode(encrypted_data)
        decrypted_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode('utf-8')

