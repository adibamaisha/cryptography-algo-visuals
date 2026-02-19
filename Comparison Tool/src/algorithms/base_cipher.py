import time
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, List  # Add this import

class BaseCipher(ABC):
    """Base class for all cryptographic algorithms"""
    
    def __init__(self, name: str):
        self.name = name
        self.supported_key_sizes: List[int] = []
        self.supported_modes: List[str] = []
    
    @abstractmethod
    def encrypt_file(self, file_path: str, key: bytes, **kwargs) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def decrypt_file(self, file_path: str, key: bytes, **kwargs) -> Dict[str, Any]:
        pass
    
    def _measure_performance(self, operation_func, *args, **kwargs) -> Dict[str, Any]:
        """Helper method to measure performance of operations"""
        start_time = time.time()
        start_memory = self._get_memory_usage()
        
        result = operation_func(*args, **kwargs)
        
        end_time = time.time()
        end_memory = self._get_memory_usage()
        
        result.update({
            'processing_time': end_time - start_time,
            'memory_used_mb': (end_memory - start_memory) / (1024 * 1024),
            'algorithm': self.name
        })
        
        return result
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        import psutil
        process = psutil.Process(os.getpid())
        return process.memory_info().rss
    
    def get_algorithm_info(self) -> Dict[str, Any]:
        """Return information about the algorithm"""
        return {
            'name': self.name,
            'supported_key_sizes': self.supported_key_sizes,
            'supported_modes': self.supported_modes,
            'type': self.__class__.__name__
        }