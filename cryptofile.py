import hashlib
import itertools
import tempfile
from io import BytesIO, RawIOBase
from typing import Iterable


MEGABYTE = 1024 * 1024


class HashVerificationError(Exception):
    correct_hash: bytes
    actual_hash: bytes


def encrypt_block(data: Iterable[int], key: Iterable[int]) -> bytes:
    res = b''
    for byte in data:
        keychar = next(key)
        res += bytes([(byte + keychar) % 256])
    return res


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
    res = b''
    for byte in data:
        keychar = next(key)
        res += bytes([(byte - keychar) % 256])
    return res


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
