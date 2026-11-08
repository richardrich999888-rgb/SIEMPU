"""One bounded request over inherited pipes; managed endpoint only, no network API."""
import base64
import hashlib
import json
import re
import sys

import pkcs11
from pkcs11 import Attribute as A, ObjectClass as O, KeyType as K, Mechanism as M
from pkcs11 import MechanismFlag as F, KDF
from pkcs11.util.ec import encode_named_curve_parameters, encode_ec_public_key


class Rejected(Exception):
    pass


def require(condition):
    if not condition:
        raise Rejected()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(value, size):
    require(isinstance(value, str))
    data = base64.b64decode(value, validate=True)
    require(len(data) == size and base64.b64encode(data).decode() == value)
    return data


def keys(session, key_id, purpose):
    pub = session.get_key(object_class=O.PUBLIC_KEY, key_type=K.EC, id=key_id)
    priv = session.get_key(object_class=O.PRIVATE_KEY, key_type=K.EC, id=key_id)
    for attr in (A.SENSITIVE, A.ALWAYS_SENSITIVE, A.NEVER_EXTRACTABLE, A.LOCAL):
        require(priv[attr] is True)
    require(priv[A.EXTRACTABLE] is False)
    require(priv[A.SIGN] == (purpose == 'sign'))
    require(priv[A.DERIVE] == (purpose == 'deriveBits'))
    require(pub[A.EC_PARAMS] == encode_named_curve_parameters('secp256r1'))
    der = encode_ec_public_key(pub)
    return priv, der


def run(r):
    required = {'version', 'operation', 'module', 'tokenLabel', 'tokenSerial', 'pin', 'id', 'purpose'}
    extras = {'generate': set(), 'open': set(), 'sign': {'data', 'publicSha256'},
              'derive': {'data', 'publicSha256'}}
    require(isinstance(r, dict) and r.get('operation') in extras)
    require(set(r) == required | extras[r['operation']] and r['version'] == 1)
    require(isinstance(r['id'], str) and re.fullmatch('[a-f0-9]{32}', r['id']))
    require(r['purpose'] in ('sign', 'deriveBits'))
    require(isinstance(r['pin'], str) and 1 <= len(r['pin']) <= 256)
    require(isinstance(r['module'], str) and r['module'].startswith('/'))
    require(isinstance(r['tokenLabel'], str) and 1 <= len(r['tokenLabel']) <= 32)
    require(isinstance(r['tokenSerial'], str) and 1 <= len(r['tokenSerial']) <= 32)
    token = pkcs11.lib(r['module']).get_token(token_label=r['tokenLabel'], token_serial=r['tokenSerial'].encode())
    key_id = bytes.fromhex(r['id'])
    with token.open(rw=r['operation'] == 'generate', user_pin=r['pin']) as session:
        if r['operation'] == 'generate':
            require(not list(session.get_objects({A.ID: key_id})))
            params = session.create_domain_parameters(K.EC,
                {A.EC_PARAMS: encode_named_curve_parameters('secp256r1')}, local=True)
            purpose = r['purpose']
            params.generate_keypair(id=key_id, label='SIEPMU-' + purpose, store=True,
                capabilities=F.SIGN | F.VERIFY if purpose == 'sign' else F.DERIVE,
                private_template={A.SENSITIVE: True, A.EXTRACTABLE: False,
                                  A.SIGN: purpose == 'sign', A.DERIVE: purpose == 'deriveBits'})
        private, public = keys(session, key_id, r['purpose'])
        if r['operation'] in ('open', 'generate'):
            return {'publicKey': base64.b64encode(public).decode()}
        require(hashlib.sha256(public).hexdigest() == r['publicSha256'])
        if r['operation'] == 'sign':
            require(r['purpose'] == 'sign')
            result = private.sign(decode(r['data'], 32), mechanism=M.ECDSA)
            require(len(result) == 64)
        else:
            require(r['purpose'] == 'deriveBits')
            peer = decode(r['data'], 65)
            require(peer[0] == 4)
            # Only a derived ephemeral session secret is extractable. The private EC key is not.
            derived = private.derive_key(K.GENERIC_SECRET, 256, mechanism=M.ECDH1_DERIVE,
                mechanism_param=(KDF.NULL, None, peer),
                template={A.SENSITIVE: False, A.EXTRACTABLE: True, A.TOKEN: False})
            try:
                result = derived[A.VALUE]
                require(len(result) == 32)
            finally:
                derived.destroy()
        return {'data': base64.b64encode(result).decode()}


try:
    request = sys.stdin.buffer.read(8193)
    require(0 < len(request) <= 8192)
    response = {'version': 1, 'ok': True, **run(json.loads(request, object_pairs_hook=unique))}
except Exception:
    # Never serialize a native exception, a PIN, object metadata or a host path.
    response = {'version': 1, 'ok': False, 'code': 'PKCS11_OPERATION_FAILED'}
sys.stdout.write(json.dumps(response, separators=(',', ':')) + '\n')
