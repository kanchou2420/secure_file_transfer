from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class AESHandler:
    """
    AES-GCM encryption/decryption handler
    NOTE: Sử dụng AES-GCM mode để đảm bảo tính toàn vẹn
    """
    
    def __init__(self, key_size=32):  # 256-bit key
        self.key_size = key_size
    
    def generate_key(self):
        """Generate random AES key"""
        return get_random_bytes(self.key_size)
    
    def encrypt(self, data, key):
        """
        Encrypt data using AES-GCM
        Returns: dict with nonce, ciphertext, and tag
        """
        try:
            if isinstance(data, str):
                data = data.encode()
            
            # Generate random nonce
            nonce = get_random_bytes(12)  # 96-bit nonce for GCM
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt and get tag
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            return {
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'tag': base64.b64encode(tag).decode()
            }
        except Exception as e:
            raise Exception(f"AES encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data, key):
        """
        Decrypt data using AES-GCM
        encrypted_data: dict with nonce, ciphertext, and tag
        """
        try:
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext.decode()
        except Exception as e:
            raise Exception(f"AES decryption failed: {str(e)}")

