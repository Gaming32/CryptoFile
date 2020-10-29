import hashlib
import itertools
import tempfile
from io import BytesIO, RawIOBase
from typing import Iterable, Optional


MEGABYTE = 1024 * 1024


class HashVerificationError(Exception):
    correct_hash: bytes
    actual_hash: bytes


def encrypt_block(data: Iterable[int], key: Iterable[int]) -> bytes:
    return bytes((b + next(key)) % 256 for b in data)


def encrypt(infile: RawIOBase, outfile: RawIOBase, key=None, chunksize=MEGABYTE):
    if not infile.seekable():
        raise TypeError('infile must be seekable')

    start_position = infile.tell()
    hash_ = hashlib.sha256()

    while True:
        chunk = infile.read(chunksize)
        if not chunk:
            break
        hash_.update(chunk)

    digest = hash_.digest()
    outfile.write(digest)

    hash_ = hashlib.sha256(digest)
    if key is not None:
        hash_.update(key)

    infile.seek(start_position)
    usekey = itertools.cycle(hash_.digest())
    while True:
        chunk = infile.read(chunksize)
        if not chunk:
            break
        outfile.write(encrypt_block(chunk, usekey))


def decrypt_block(data: Iterable[int], key: Iterable[int]) -> bytes:
    return bytes([(b - next(key)) % 256 for b in data])


def decrypt(infile: RawIOBase, outfile: RawIOBase, key=None, verify_hash=True, chunksize=MEGABYTE):
    stored_hash = infile.read(32)
    hash_ = hashlib.sha256(stored_hash)
    if key is not None:
        hash_.update(key)

    verification_hash = hashlib.sha256()

    usekey = itertools.cycle(hash_.digest())
    while True:
        chunk = infile.read(chunksize)
        if not chunk:
            break
        decrypted_block = decrypt_block(chunk, usekey)
        outfile.write(decrypted_block)
        verification_hash.update(decrypted_block)

    if verify_hash:
        verification_digest = verification_hash.digest()
        if verification_digest != stored_hash:
            exc = HashVerificationError('Stored hash does not match decrypted hash. '
                                        'The data may have been tampered with or the '
                                        'incorrect key was used to decrypt it.')
            exc.correct_hash = stored_hash
            exc.actual_hash = verification_digest
            raise exc


class EncryptedFile(RawIOBase):
    def __init__(self, name, mode='r', key:bytes = None, verify_hash=True, chunksize=MEGABYTE, tempobj: RawIOBase = None):
        self._wrapped = open(name, mode + 'b')
        if tempobj is None:
            tempobj = tempfile.SpooledTemporaryFile(chunksize)
            tempobj.seekable = (lambda: True) # Fix for BPO-35112
        self._temp = tempobj
        if 'r' in mode or '+' in mode:
            decrypt(self._wrapped, self._temp, key, verify_hash, chunksize)
        # self._temp2 = tempfile.SpooledTemporaryFile(chunksize)
        self.name = name
        self.mode = mode
        self.key = key
        self.verify_hash = verify_hash
        self.chunksize = chunksize
        self._closed = False

    def read(self, size: int = None) -> bytes:
        return self._temp.read(size)

    def write(self, b: bytes) -> int:
        return self._temp.write(b)
    
    def seek(self, offset: int, whence: int = 0) -> int:
        return self._temp.seek(offset, whence)

    def tell(self) -> int:
        return self._temp.tell()
    
    def flush(self):
        if 'w' not in self.mode or '+' not in self.mode:
            return
        if self._closed:
            raise ValueError('I/O operation on closed file.')
        self._temp.seek(0)
        self._wrapped.seek(0)
        return encrypt(self._temp, self._wrapped, self.key, self.chunksize)
    
    def seekable(self) -> bool:
        return self._temp.seekable()
    
    def readable(self) -> bool:
        return self._wrapped.readable()
    
    def writable(self) -> bool:
        return self._wrapped.writable()
    
    def close(self):
        self.flush()
        self._closed = True
        self._temp.close()
        self._wrapped.close()

    def __del__(self):
        if self._closed:
            return
        self.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *exc_info) -> Optional[bool]:
        return


if __name__ == '__main__':
    stream = BytesIO(input('Data to encrypt/decrypt: ').encode('latin-1'))
    print('Before encrypt:', stream.getvalue())

    key = input('Key to use: ').encode('latin-1')

    encrypted_data = BytesIO()
    encrypt(stream, encrypted_data, key)
    encrypted_data.seek(0)
    print('After encrypt:', encrypted_data.getvalue())

    decrypted_data = BytesIO()
    decrypt(encrypted_data, decrypted_data, key)
    decrypted_data.seek(0)
    print('After decrypt:', decrypted_data.getvalue())
