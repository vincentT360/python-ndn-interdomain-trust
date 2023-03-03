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

lvs_text = r'''
#KEY: "KEY"/_/_/_
#site: lvs & {lvs: "lvs-test"|"lvs-test2"}
#article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
#author: #site/"author"/author/"KEY"/_/admin/_ <= #admin
#admin: #site/"admin"/admin/#KEY <= #root
#por: "lvs-test2"/"KEY"/_/"x07nx08x08lvs-test"/_ <= #root
#root: #site/#KEY
'''

#Modified "#site" so trust schema now follows chain of trust for packets from lvs-test and lvs-test2
#But it will fail when reaching lvs-test2 trust anchor because that trust anchor differs from ours.

def main():
    
    keychain = KeychainSqlite3("/home/vince/.ndn/pib.db", TpmFile("/home/vince/.ndn/ndnsec-key-file"))

    trust_anchor = keychain['/lvs-test'].default_key().default_cert()

    print(f'Trust anchor name: {Name.to_str(trust_anchor.name)}')

    lvs_model = compile_lvs(lvs_text)
    checker = Checker(lvs_model, DEFAULT_USER_FNS)
    app = NDNApp(keychain=keychain)

    validator = lvs_validator(checker, app, trust_anchor.data)
    logging.debug("Done creating validator")

    async def fetch_interest(article: str):
        try:
            name = Name.from_str(f'/lvs-test2/article/vincent/{article}')
            print(f'Sending Interest {Name.to_str(name)}')
            logging.debug("Sending Interest")
            data_name, meta_info, content = await app.express_interest(
                name, must_be_fresh=True, can_be_prefix=True, lifetime=6000,
                validator=validator) #Need to examine the validator
            print(f'Received Data Name: {Name.to_str(data_name)}')
            print(meta_info)
            print(bytes(content).decode() if content else None)
        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print(f'Timeout')
        except InterestCanceled:
            print(f'Canceled')
        except ValidationFailure:
            print(f'Data failed to validate')

    async def ndn_main():
        await fetch_interest('hello')
        #await fetch_interest('world')

        app.shutdown()

    app.run_forever(ndn_main())


if __name__ == '__main__':
    main()