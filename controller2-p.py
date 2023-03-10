#Controller producer entity living in /lvs-test2 domain
#It provides the /lvs-test2 trust anchor to controller 1

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

    #Get trust anchor key
    trust_anchor = keychain['/lvs-test2'].default_key().default_cert()
    
    print(f'Serving trust anchor name: {Name.to_str(trust_anchor.name)}')
    
    app = NDNApp(keychain=keychain)

    #@app.route(trust_anchor.name)
    '''
    For some reason, I have to use this /lvs-test2/KEY/ specifically because the network wont work with can_be_prefix on trust_anchor.name
    As controller of /lvs-test doesn't know the full TA details of /lvs-test2, I tried using can_be_prefix to fetch it with part of the name
    But it did not work, so I resorted to this
    '''
    @app.route('/lvs-test2/KEY/')
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(trust_anchor.data)
        print(f'<< D: {Name.to_str(trust_anchor.name)}')
        print('')

    print('Start serving ...')
    app.run_forever()
    

if __name__ == '__main__':
    main()