#[Project code]:
#Controller producer entity living in /lvs-test domain
#It provides the PoR to entities in its own domain
import os
import sys
import logging
from ndn.utils import timestamp
from ndn.encoding import Name, Component
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app import NDNApp
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

def main():
    keychain = KeychainSqlite3("/home/vince/.ndn/pib.db", TpmFile("/home/vince/.ndn/ndnsec-key-file"))

    #Fetch PoR from keychain
    proof_of_domain_recognition = keychain['/lvs-test2'].default_key()[f'/lvs-test2/KEY/%D9%A1%2A%F3V%3D%25%F7/7=%08%08lvs-test/v=1678663087543']
    
    print(f'PoR name: {Name.to_str(proof_of_domain_recognition.name)}')

    app = NDNApp(keychain=keychain)

    @app.route(proof_of_domain_recognition.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(proof_of_domain_recognition.data)
        print(f'<< D: {Name.to_str(proof_of_domain_recognition.name)}')
        print('')

    print('Start serving ...')
    app.run_forever()

if __name__ == '__main__':
    main()