# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import abc
import logging
from typing import Optional, Coroutine, Any
from Cryptodome.PublicKey import ECC, RSA
from ...encoding import FormalName, BinaryStr, SignatureType, Name, parse_data, SignaturePtrs
from ...app import NDNApp, Validator, ValidationFailure, InterestTimeout, InterestNack
from .known_key_validator import verify_rsa, verify_hmac, verify_ecdsa
from ndn.app_support.light_versec import Checker

class PublicKeyStorage(abc.ABC):
    @abc.abstractmethod
    def load(self, name: FormalName) -> Optional[bytes]:
        pass

    @abc.abstractmethod
    def save(self, name: FormalName, key_bits: bytes):
        pass


class EmptyKeyStorage(PublicKeyStorage):
    def load(self, name: FormalName) -> Optional[bytes]:
        return None

    def save(self, name: FormalName, key_bits: bytes):
        return


class MemoryKeyStorage(PublicKeyStorage):
    _cache: dict[bytes, bytes]

    def __init__(self):
        self._cache = {}

    def load(self, name: FormalName) -> Optional[bytes]:
        return self._cache.get(Name.to_bytes(name), None)

    def save(self, name: FormalName, key_bits: bytes):
        self._cache[Name.to_bytes(name)] = key_bits


class CascadeChecker:
    app: NDNApp
    next_level: Validator
    storage: Optional[PublicKeyStorage]
    anchor_key: bytes
    anchor_name: FormalName

    @staticmethod
    def _verify_sig(pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type == SignatureType.HMAC_WITH_SHA256:
            verify_hmac(pub_key_bits, sig_ptrs)
        elif sig_ptrs.signature_info.signature_type == SignatureType.SHA256_WITH_RSA:
            pub_key = RSA.import_key(bytes(pub_key_bits))
            return verify_rsa(pub_key, sig_ptrs)
        elif sig_ptrs.signature_info.signature_type == SignatureType.SHA256_WITH_ECDSA:
            pub_key = ECC.import_key(bytes(pub_key_bits))
            return verify_ecdsa(pub_key, sig_ptrs)
        else:
            return False
        

    def __init__(self, app: NDNApp, trust_anchor: BinaryStr, storage: PublicKeyStorage = MemoryKeyStorage(), checker: Optional[Checker] = None):
        self.app = app
        self.next_level = self
        self.storage = storage
        self.lvs_checker = checker #Added for interdomain PoR
        cert_name, _, key_bits, sig_ptrs = parse_data(trust_anchor)
        self.anchor_name = [bytes(c) for c in cert_name]  # Copy the name in case
        self.anchor_key = bytes(key_bits)
        if not self._verify_sig(self.anchor_key, sig_ptrs):
            raise ValueError('Trust anchor is not properly self-signed')

    async def validate(self, name: FormalName, sig_ptrs: SignaturePtrs) -> bool:
        #This function fetches key and actually verify packet
        if (not sig_ptrs.signature_info or not sig_ptrs.signature_info.key_locator
                or not sig_ptrs.signature_info.key_locator.name):
            logging.debug('[Cascade_validator]: If not sig_ptrs')
            print('[Cascade_validator]: If not sig_ptrs, returning False')
            return False
        cert_name = sig_ptrs.signature_info.key_locator.name
        logging.debug(f'Verifying {Name.to_str(name)} <- {Name.to_str(cert_name)} ...')
        print(f'[Cascade-validator]: Verifying {Name.to_str(name)} <- {Name.to_str(cert_name)}')

        #Different validate scenarios
        #1. identity <- foreign ta: Fetch PoR
        #2. identity <- local ta: Compare against my hardcoded ta
        #3. identity <- idenity: Fetch the other identity

        #This is used to test inter-domain
        #Bc lvs-test domain trust anchor is /lvs-test it fails to recognize /lvs-test2 trust anchor
        #This is just a cheap way to accept the packet signed by /lvs-test2 trust anchor.
        #Meaning that since this returns True, the whole chain is accepted and so does the packet. We probbaly need to do PoR stuff here.
        #if Name.to_str(cert_name) == "/lvs-test2/KEY/%D9%A1%2A%F3V%3D%25%F7/self/v=1677033715766":
        #    print("--------------------------------------")
        #    return True

        #1. Detect that the certificate signing this key is a trust anchor of another domain that we accept according to trust schema
        # identity <- trust b anchor
        #[CS 217b Project]
        root_of_trust = self.lvs_checker.root_of_trust()
        ta_matches = sum((m[0] for m in self.lvs_checker.match(cert_name)), start=[])
        if cert_name != self.anchor_name and root_of_trust.issubset(ta_matches):
            print(f"[Cas_Validator] HIT SOME VALID TRUST ANCHOR that is not my trust anchor")            
            #2. Build the PoR name
            #Need 2 pieces: key name of the foreign trust anchor, my own domain name

            foreign_ta = Name.to_str(cert_name).split('/')
            foreign_ta_key_name = "/".join(foreign_ta[:foreign_ta.index('KEY')+2])
            local_ta = Name.to_str(self.anchor_name).split('/')
            local_ta_domain_name = "/".join(local_ta[:local_ta.index('KEY')])
           
            #Name building is somewhat convuluted due the local domain needing to be stored in TLV encoding
            por_name = Name.normalize(foreign_ta_key_name) + [Name.to_bytes(local_ta_domain_name)]

            #3. Fetch the PoR
            try:
                    #Fetch via can_be_prefix does not seem to work
                    _, _, key_bits = await self.app.express_interest(
                        name=Name.to_str(por_name)+"/v=1678663087543", must_be_fresh=True, can_be_prefix=True,
                        validator=self.next_level)
                    #Next level will check PoR against the schema AND also validate it using our own trust anchor

                    #If this await does not except and passes, it means the PoR passed validation.
                    #This implies that this level has also passed verification because we verified its certificate.
                    print(f'[Cascade_validator] verifying sig return: True for {Name.to_str(name)} <- {Name.to_str(cert_name)}')
                    return True
            except (ValidationFailure, InterestTimeout, InterestNack) as e:
                    logging.debug('Public key not valid.')
                    print(f'[Cascade_validator] is raising an error while fetching PoR')
                    print(e)
                    return False
            
        #If certificate signing this key is same as trust anchor for my domain, then just check against my trust anchor.
        if cert_name == self.anchor_name:
            logging.debug('Use trust anchor.')
            print(f'[Cascade_validator] using trust anchor for {Name.to_str(name)} <- {Name.to_str(cert_name)}')
            key_bits = self.anchor_key
        #Else, it cannot be trust anchor (or it is an unrecognized trust anchor in the interdomain case) so we need to fetch the key.
        else:
            if key_bits := self.storage.load(cert_name):
                logging.debug('Use cached public key.')
                print(f'[Cascade_validator] using cached public key for {Name.to_str(name)} <- {Name.to_str(cert_name)}')
            else:
                logging.debug('Cascade fetching public key ...')
                print(f'[Cascade_validator] fetching public key for {Name.to_str(name)} by expressing interest for {Name.to_str(cert_name)}')
                # Try to fetch
                try:
                    _, _, key_bits = await self.app.express_interest(
                        name=cert_name, must_be_fresh=True, can_be_prefix=False,
                        validator=self.next_level)
                    #This express_interest fetches the public key to verify the current signature for this packet name.
                    #But then it also needs to verify that public key, b/c that public key has a name that is signed.

                    #E.g First it wants to check (data name article) <- (signature by author).
                    #It goes to get author public key to verify the sig. Once it gets it it verfiies.

                    #But when getting author it expresses a interest for a data packet with the name author. (Data name author) <- (signature by admin). Verify sig when we get admin key.
                    #So then we also need to fetch admin. So we have (data name admin) <- (signature trust anchor).

                    #In this case it makes a total of 2 fetches, one for author and one for admin.
                    #Then when it sees the cert_name is trust anchor (e.g when checking admin) it just compares against trust anchor (does not fetch), bc if it did it would get the self signed cert which makes no sense.
                    #Note: It only stops if the trust anchor is one it recognizes, else it will continue and do trust anchor <- self signed.
                except (ValidationFailure, InterestTimeout, InterestNack) as e:
                    logging.debug('Public key not valid.')
                    print(f'[Cascade_validator] is raising an error for {Name.to_str(name)} <- {Name.to_str(cert_name)}, returning False {type(e)}')
                    return False
                logging.debug('Public key fetched.')
                if key_bits:
                    self.storage.save(cert_name, key_bits)

        # Validate signature
        if not key_bits:
            logging.debug('[Cascade_validator] If not key_bits')
            print(f'[Cascade_validator] found no key bits for {Name.to_str(name)} <- {Name.to_str(cert_name)}, returning false')
            return False
        
        print(f'[Cascade_validator] verifying sig return: {self._verify_sig(key_bits, sig_ptrs)} for {Name.to_str(name)} <- {Name.to_str(cert_name)}')
        return self._verify_sig(key_bits, sig_ptrs)

    def __call__(self, name: FormalName, sig_ptrs: SignaturePtrs) -> Coroutine[Any, None, bool]:
        return self.validate(name, sig_ptrs)
