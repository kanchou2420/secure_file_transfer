from Crypto.Hash import SHA512
import hashlib

class HashHandler:
    """
    SHA-512 hashing handler
    NOTE: Dùng để kiểm tra tính toàn vẹn của dữ liệu
    """
    
    @staticmethod
    def hash_data(data):
        """
        Hash data using SHA-512
        Returns hex string
        """
        if isinstance(data, str):
            data = data.encode()
        
        return hashlib.sha512(data).hexdigest()
    
    @staticmethod
    def hash_file_packet(nonce, ciphertext, tag):
        """
        Hash file packet (nonce || ciphertext || tag)
        NOTE: Theo đúng protocol yêu cầu
        """
        combined = nonce + ciphertext + tag
        return HashHandler.hash_data(combined)
    
    @staticmethod
    def verify_hash(data, expected_hash):
        """Verify hash integrity"""
        actual_hash = HashHandler.hash_data(data)
        return actual_hash == expected_hash