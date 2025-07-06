from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
import base64

class RSAHandler:
    """
    RSA encryption/decryption handler
    NOTE: Sử dụng RSA 1024-bit với OAEP padding và SHA-512
    """
    
    def generate_keypair(self):
        """Generate RSA 1024-bit key pair"""
        key = RSA.generate(1024)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        return {
            'private': base64.b64encode(private_key).decode(),
            'public': base64.b64encode(public_key).decode()
        }
    
    def encrypt(self, data, public_key_b64):
        """Encrypt data using RSA-OAEP"""
        try:
            public_key_pem = base64.b64decode(public_key_b64)
            public_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512)
            
            if isinstance(data, str):
                data = data.encode()
            
            encrypted = cipher.encrypt(data)
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise Exception(f"RSA encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data_b64, private_key_b64):
        """Decrypt data using RSA-OAEP"""
        try:
            private_key_pem = base64.b64decode(private_key_b64)
            private_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)
            
            encrypted_data = base64.b64decode(encrypted_data_b64)
            decrypted = cipher.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            raise Exception(f"RSA decryption failed: {str(e)}")
    
    def sign(self, data, private_key_b64):
        """Sign data using RSA with SHA-512"""
        try:
            private_key_pem = base64.b64decode(private_key_b64)
            private_key = RSA.import_key(private_key_pem)
            
            if isinstance(data, str):
                data = data.encode()
            
            h = SHA512.new(data)
            signature = pkcs1_15.new(private_key).sign(h)
            return base64.b64encode(signature).decode()
        except Exception as e:
            raise Exception(f"RSA signing failed: {str(e)}")
    
    def verify(self, data, signature_b64, public_key_b64):
        """Verify signature using RSA with SHA-512"""
        try:
            public_key_pem = base64.b64decode(public_key_b64)
            public_key = RSA.import_key(public_key_pem)
            
            if isinstance(data, str):
                data = data.encode()
            
            h = SHA512.new(data)
            signature = base64.b64decode(signature_b64)
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except Exception:
            return False