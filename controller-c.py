#[Project code]:
#Controller consumer entity living in /lvs-test domain
#It handles PoR creation

import os
import sys
import logging
from ndn.utils import timestamp
from ndn.encoding import FormalName, BinaryStr, SignatureType, Name, parse_data, SignaturePtrs
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app import NDNApp, InterestNack, InterestTimeout, InterestCanceled, ValidationFailure
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS, lvs_validator


logging.basicConfig(filename="logInterdomain.txt",
                    format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = NDNApp()

def main():
    
    keychain = KeychainSqlite3("/home/vince/.ndn/pib.db", TpmFile("/home/vince/.ndn/ndnsec-key-file"))
    trust_anchor = keychain['/lvs-test'].default_key()

    app = NDNApp()

    async def fetch_trust_anchor(anchor: str):
        try:
            print(f'Sending Interest {anchor}')
            logging.debug("Sending Interest")
            data_name, _, key_bits = await app.express_interest(
                name=anchor, must_be_fresh=True, can_be_prefix=True)
            return data_name
        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print(f'Timeout')
        except InterestCanceled:
            print(f'Canceled')
        except ValidationFailure:
            print(f'Data failed to validate')

    async def ndn_main():
        await generate_PoR()

        app.shutdown()
    
    async def generate_PoR():
        local_domain = '/lvs-test'
        foreign_domain = '/lvs-test2'

        #Fetch controller 2's trust anchor
        #data_name is the cert name of the foreign trust anchor contains domain and keyid which we need /domain/key/key_id/...
        #key_bits is the public key of the foreign trust anchor
        data_name = await fetch_trust_anchor(f'{foreign_domain}/KEY/')
        print("Fetched", Name.to_str(data_name))

        data_name = Name.to_str(data_name).split('/')

        foreign_domain_key_id = data_name[data_name.index('KEY')+1]
        foreign_domain_key_name = f'{foreign_domain}/KEY/{foreign_domain_key_id}'

        #Check if identity or key already exists, if not create them.
        if foreign_domain in keychain:
            print("Identity already exists")
            if foreign_domain_key_name in keychain[foreign_domain]:
                print("Key already exists")
            else:
                keychain.new_key(foreign_domain, key_id=foreign_domain_key_id)
        else:
            keychain.new_identity(foreign_domain)
            keychain.new_key(foreign_domain, key_id=foreign_domain_key_id)

        #Now create the PoR, it needs various components to sign
        #PoR: foreign_domain_key_name/local_domain/version <-(signed by) my trust anchor
        keychain.sign_PoR(foreign_domain, foreign_domain_key_name, Name.to_str(trust_anchor.name), local_domain)

    app.run_forever(ndn_main())


if __name__ == '__main__':
    main()