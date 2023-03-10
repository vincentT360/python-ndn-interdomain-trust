#Controller consumer entity living in /lvs-test domain
#It handles PoR creation

"""
Goals

1. Have controller 1 authenticate controller 2
- I think done out of band?

2. Have controller 1 fetch trust anchor for domain 2 from controller 2
- Controller 1 expresses an interest

3. Have controller 1 sign it and store it as PoR

"""

#Consumer entity living in /lvs-test domain
#Expresses interest to fetch data from /lvs-test2

import os
import sys
import logging
from ndn.utils import timestamp
from ndn.encoding import Name, Component, InterestParam
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

    app = NDNApp()

    async def fetch_trust_anchor(anchor: str):
        try:
            print(f'Sending Interest {anchor}')
            logging.debug("Sending Interest")
            data_name, meta_info, content = await app.express_interest(
                name=anchor, must_be_fresh=True, can_be_prefix=True)
            print(f'Got data with name: {Name.to_str(data_name)}')
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
        #Fetch controller 2's trust anchor
        #data_name is the name of its trust anchor
        data_name = await fetch_trust_anchor('/lvs-test2/KEY/')
        print("Other trust anchor: ", Name.to_str(data_name))

        #After fetching, figure out how to build the PoR name, sign it, and store it into the keychain
        #Paper has the naming format
        

        app.shutdown()

    app.run_forever(ndn_main())


if __name__ == '__main__':
    main()