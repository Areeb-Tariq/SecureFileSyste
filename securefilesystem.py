from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from random import randint
import os
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Reference: https://ieeexplore.ieee.org/document/8576289

# Method to generate 512 bit elGamal public and private keys
# eference: https://github.com/pycrypto/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py
def generateElgamalKey(bits=512):
  
    # Getting a large prime number
    p = getPrime(bits)  
    # Getting a generator
    g = randint(2, p - 1) 
    # Private key
    x = randint(1, p - 2) 
    # Public key component
    y = pow(g, x, p)  
    public_key = (p, g, y)
    private_key = (p, g, x)
    return public_key, private_key

# Encrypt AES key using elGamal
def encryptAesKey(aes_key, public_key):
    
    p, g, y = public_key
    # Generating a random number
    k = randint(1, p - 2)  
    c1 = pow(g, k, p)
    c2 = (bytes_to_long(aes_key) * pow(y, k, p)) % p
    return (c1, c2)

# Decrypt AES key using elGamal
def decryptAesKey(encrypted_key, private_key):
    # Decrypt the AES key using ElGamal
    p, g, x = private_key
    c1, c2 = encrypted_key
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    aes_key_long = (c2 * s_inv) % p
    return long_to_bytes(aes_key_long)

# Encrypt a file using AES
def encryptFile(filepath, aes_key):
    #Encrypt the contents of a file with AES
    try:
      # AES initialization vector
        iv = get_random_bytes(16)  
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        with open(filepath, 'rb') as f:
            data = f.read()
        encrypted_data = iv + cipher.encrypt(pad(data, AES.block_size))
        with open(filepath + ".enc", 'wb') as f:
            f.write(encrypted_data)
        print(f"File '{filepath}' encrypted successfully!")
    except Exception as e:
        print(f"Error encrypting file {filepath}: {e}")

# Decrypt a file using AES
# Reference: https://medium.com/@giritharram005/247ctf-cryptography-part-3-5797e270eed8
def decryptFile(filepath, aes_key):
    #Decrypt the file with AES
    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        # Extracting the IV    
        iv = encrypted_data[:16]  
         # Extracting the ciphertext
        ciphertext = encrypted_data[16:] 
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        with open(filepath.replace(".enc", ""), 'wb') as f:
            f.write(decrypted_data)
        print(f"File '{filepath}' decrypted successfully!")
    except Exception as e:
        print(f"Error decrypting file {filepath}: {e}")

# Encrypt all files in a folder
def encryptFolder(folder_path, aes_key):
   
    try:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                encryptFile(file_path, aes_key)
    except Exception as e:
        print(f"Error encrypting folder {folder_path}: {e}")


# Save ElGamal keys to files
def saveElgamalKeys(public_key, private_key, public_key_file, private_key_file):
   
    try:
        # Ensure the 'keys' directory exists, create it if it doesn't
        if not os.path.exists('keys'):
            os.makedirs('keys')

        # Construct the full file paths for public and private keys
        public_key_path = os.path.join('keys', public_key_file)
        private_key_path = os.path.join('keys', private_key_file)
        
        # Save the public and private keys to the files
        with open(public_key_path, 'wb') as f:
            f.write(bytes(str(public_key), 'utf-8'))
        with open(private_key_path, 'wb') as f:
            f.write(bytes(str(private_key), 'utf-8'))
        
        print(f"ElGamal keys saved to '{public_key_path}' and '{private_key_path}'")
    except Exception as e:
        print(f"Error saving keys: {e}")

# Load ElGamal keys from files
def loadElgamalKeys(public_key_file, private_key_file):
    
    try:
        # Construct the full file paths for public and private keys
        public_key_path = os.path.join('keys', public_key_file)
        private_key_path = os.path.join('keys', private_key_file)
        
        # Read and load the public and private keys from the files
        with open(public_key_path, 'rb') as f:
            public_key = eval(f.read().decode())
        with open(private_key_path, 'rb') as f:
            private_key = eval(f.read().decode())
        
        print(f"ElGamal keys loaded from '{public_key_path}' and '{private_key_path}'")
        return public_key, private_key
    except Exception as e:
        print(f"Error loading keys: {e}")
        return None, None

# Sign the ecrypted file using the  RSA private key
def sign_file(file_path, private_key):
    """Sign a file using RSA private key."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        hash_obj = SHA256.new(data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        with open(file_path + ".sig", 'wb') as f:
            f.write(signature)
        print(f"File '{file_path}' signed successfully!")
    except Exception as e:
        print(f"Error signing file {file_path}: {e}")

# Function to verify a file signature using RSA public key
def verify_file_signature(file_path, public_key):
    """Verify the file signature using RSA public key."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        signature_path = file_path + ".sig"
        with open(signature_path, 'rb') as f:
            signature = f.read()
        
        hash_obj = SHA256.new(data)
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print(f"Signature for '{file_path}' is valid!")
    except (ValueError, TypeError):
        print(f"Invalid signature for '{file_path}'")
    except Exception as e:
        print(f"Error verifying signature for {file_path}: {e}")        

# Main Function
if __name__ == "__main__":
    # Generating ElGamal keys for two users
    user1_key, user1_private_key = generateElgamalKey()
    user2_key, user2_private_key = generateElgamalKey()

    # Saving keys to files
    saveElgamalKeys(user1_key, user1_private_key, 'user1_pub.key', 'user1_priv.key')
    saveElgamalKeys(user2_key, user2_private_key, 'user2_pub.key', 'user2_priv.key')

    # Loading keys from files
    user1_key, user1_private_key = loadElgamalKeys('user1_pub.key', 'user1_priv.key')
    user2_key, user2_private_key = loadElgamalKeys('user2_pub.key', 'user2_priv.key')

    # Generating random AES key for file encryption
    aes_key = get_random_bytes(32)  # 256-bit AES key

    # Encrypting the AES key using ElGamal (User 2's public key)
    encrypted_aes_key = encryptAesKey(aes_key, user2_key)

    # Encrypting and sign a file (example.txt)
    encryptFile("example.txt", aes_key)

    
      
  
    # Decrypting the AES key using User 2's private key
    decrypted_aes_key = decryptAesKey(encrypted_aes_key, user2_private_key)

    # Decrypting the file
    decryptFile("example.txt.enc", decrypted_aes_key)
