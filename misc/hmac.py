def compute_hmac_sha256(key: bytes, *buffers) -> bytes:
    _hmac = HMAC.new(key, digestmod=SHA256.new())
    for b in buffers:
        _hmac.update(b)
    return _hmac.digest()

def verify_hmac_sha256(key: bytes, hmac_value: bytes, *buffers):
    _hmac = compute_hmac_sha256(key, *buffers)
    return _hma == hmac_value