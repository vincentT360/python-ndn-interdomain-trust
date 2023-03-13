# -----------------------------------------------------------------------------
# This piece of work is inspired by Pollere' VerSec:
# https://github.com/pollere/DCT
# But this code is implemented independently without using any line of the
# original one, and released under Apache License.
#
# Copyright (C) 2019-2022 The python-ndn authors
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
import logging
from ...encoding import BinaryStr, SignaturePtrs, FormalName, parse_data, Name
from ...app import NDNApp, Validator
from ...security import union_checker
from ...security.validator.cascade_validator import CascadeChecker, PublicKeyStorage, MemoryKeyStorage
from .checker import Checker

__all__ = ['lvs_validator']


def lvs_validator(checker: Checker, app: NDNApp, trust_anchor: BinaryStr,
                  storage: PublicKeyStorage = MemoryKeyStorage()) -> Validator:
    async def validate_name(name: FormalName, sig_ptrs: SignaturePtrs) -> bool:
        #Make sure name conforms to LVS schema
        if (not sig_ptrs.signature_info or not sig_ptrs.signature_info.key_locator
                or not sig_ptrs.signature_info.key_locator.name):
            return False
        cert_name = sig_ptrs.signature_info.key_locator.name
        logging.debug(f'LVS Checking {Name.to_str(name)} <- {Name.to_str(cert_name)} ...')

        print(f'[LVS validate] name {Name.to_str(name)} <- {Name.to_str(cert_name)} ...')

        #Detect that we have reached the trust anchor of a valid domain by matching the #root format of lvs to trust anchor name
        #Also need to compare to make sure this is not our trust anchor so we can do the intertrust process
        #root_of_trust = checker.root_of_trust()
        #my_trust_anchor_name, _, _, _ = parse_data(trust_anchor)
        #When we match on cert-name it will show up for inter/intra domain. This is when we see admin <- root
        #Seems to imply that validate_name will not continue after it hits a trust anchor/root as a certificate.
        # (Update: this is true cas checker will stop when it notices it is signed by a trust anchor)
        #/lvs-test2/admin/ndn/KEY/6%EC%DD%DD%0ATb%DA/lvs-test2/v=1677033765106 <- /lvs-test2/KEY/%D9%A1%2A%F3V%3D%25%F7/self/v=1677033715766

        #Question: Do we stop here or do we keep on going until we reach root <- self signed? This only happens in the inter-domain case.

        #So we check if 1) the cert_name matches the lvs roots of trust and 2) it is not our current domain's trust anchor but a foreign one.
        #ta_matches = sum((m[0] for m in checker.match(name)), start=[])
        #if root_of_trust.issubset(ta_matches) and name != my_trust_anchor_name:
        #    print(f"[LVS Validate Name] Is subset result {root_of_trust.issubset(ta_matches)}, hit some valid trust anchor that is not my trust anchor")
        # Update: Now done in cascade_validator

        '''
        Intradomain case: admin <- root
        - validate_name(): True
        - checker.check(): True
        - cas_checker()  : True
        - It does not run these 3 checkers anymore after this step, and validation is complete.

        Interdomain case: admin <- root
        - validate_name(): True
        - checker.check(): True
        - cas_checker()  : False
        - It should also not run these 3 checkers anymore after this step.
        - This is because if we continue to root <- self signed, it fails validate_name, checker.check and cas_checker
        - So we should probably stay at the admin <- root level

        - This also seems to imply we need to notify cas_checker() we are in interdomain case and then to fetch. B/c this is the only failing component. We have to end it here.

        So when we detect cert_name == another domain's trust anchor
        1) Fetch PoR, which returns data name PoR <- signed by my domain's trust anchor
            - Return False if we fail to fetch
            - Else continue

        2) Compare the signature with my trust anchor.
            - Return False if it fails to compare
            - Else return True
        
        '''
        res = checker.check(name, cert_name)
        logging.debug(f'[LVS Validate Name] result: {res}')
        print(f'[LVS Validate Name] result: {res}')
        return res

    def sanity_check():
        root_of_trust = checker.root_of_trust()
        if not checker.validate_user_fns():
            raise ValueError('Missing user functions for LVS validator')
        cert_name, _, _, _ = parse_data(trust_anchor)
        ta_matches = sum((m[0] for m in checker.match(cert_name)), start=[])
        if not ta_matches or not root_of_trust.issubset(ta_matches):
            raise ValueError('Trust anchor does not match all roots of trust of LVS model')

    sanity_check()
    #We add the roots of trust to be passed along to cascade checker.
    #So we modify CascadeChecker construction function to take in root_of_trust
    root_of_trust = checker.root_of_trust() #[CS 217b Project]
    cas_checker = CascadeChecker(app, trust_anchor, storage, checker)
    ret = union_checker(validate_name, cas_checker)
    cas_checker.next_level = ret
    return ret #We are actually returning union_checker, so when we call validate it actually runs union_checker to run both validate_name and cas_checker.
