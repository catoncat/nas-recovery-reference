"""ctypes ChaCha8 adapter, with explicit NumPy fallback and original call semantics."""
import ctypes
from pathlib import Path
from file_layout import RecoveryError
from decrypt_copy import CALL_LIMIT

def load_cipher(numpy_call, library=None):
    path=Path(library) if library is not None else Path(__file__).with_name('libchacha8.so')
    try:
        lib=ctypes.CDLL(str(path))  # CDLL releases the GIL while C runs.
        lib.c3rb3r_chacha8_abi.restype=ctypes.c_int
        if lib.c3rb3r_chacha8_abi()!=1:raise RuntimeError('unsupported ChaCha8 ABI')
        lib.c3rb3r_chacha8_backend.restype=ctypes.c_char_p
        backend=lib.c3rb3r_chacha8_backend().decode('ascii')
        xor=lib.c3rb3r_chacha8_xor
        xor.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_size_t,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint64]
        xor.restype=ctypes.c_int
        def call(data,key,nonce,counter=0):
            if len(key)!=32 or len(nonce)!=8:raise RecoveryError('ChaCha8 requires a 32-byte key and 8-byte nonce')
            if len(data)>CALL_LIMIT:raise RecoveryError('One cipher call must not exceed 5 MiB')
            count=(len(data)+63)//64
            if counter<0 or counter+count>(1<<64):raise RecoveryError('ChaCha counter is outside the supported range')
            if not count:return b'',counter
            out=ctypes.create_string_buffer(len(data))
            if xor(out,data,len(data),key,nonce,counter):raise RecoveryError('native ChaCha8 failed')
            return out.raw,counter+count
        # Deterministic public inputs only. Reject an incompatible library at startup.
        for length,counter in ((1,0),(511,(1<<32)-2),(65,(1<<64)-2)):
            data=bytes(length);key=bytes(32);nonce=bytes(8)
            if call(data,key,nonce,counter)!=numpy_call(data,key,nonce,counter):raise RuntimeError('native self-check mismatch')
        return call,{'cipher_backend':backend,'cipher_library':str(path),'cipher_fallback_reason':None}
    except (OSError,AttributeError,RuntimeError,ValueError) as error:
        return numpy_call,{'cipher_backend':'numpy','cipher_library':str(path),'cipher_fallback_reason':type(error).__name__+': '+str(error)}
