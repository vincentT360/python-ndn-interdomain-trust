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

lvs_text = r'''
#KEY: "KEY"/_/_/_
#site: "lvs-test2"
#article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
#author: #site/"author"/author/"KEY"/_/admin/_ <= #admin
#admin: #site/"admin"/admin/#KEY <= #root
#root: #site/#KEY
'''


def main():
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    tpm_path = os.path.join(basedir, 'privKeys')
    pib_path = os.path.join(basedir, 'pib.db')
    keychain = KeychainSqlite3("/home/vince/.ndn/pib.db", TpmFile("/home/vince/.ndn/ndnsec-key-file"))

    trust_anchor = keychain['/lvs-test2'].default_key().default_cert()
    admin_cert = keychain['/lvs-test2/admin/ndn'].default_key().default_cert()
    author_cert = keychain['/lvs-test2/author/vincent'].default_key().default_cert()
    print(f'Trust anchor name: {Name.to_str(trust_anchor.name)}')
    print(f'Admin name: {Name.to_str(admin_cert.name)}')
    print(f'Author name: {Name.to_str(author_cert.name)}')

    lvs_model = compile_lvs(lvs_text)
    checker = Checker(lvs_model, DEFAULT_USER_FNS)
    # The following manual checks are listed for demonstration only.
    # In real implementation they are automatically done
    root_of_trust = checker.root_of_trust()
    print(f'LVS model root of trust: {root_of_trust}')
    print(f'LVS model user functions provided: {checker.validate_user_fns()}')
    ta_matches = sum((m[0] for m in checker.match(trust_anchor.name)), start=[])
    assert len(ta_matches) > 0
    assert root_of_trust.issubset(ta_matches)
    print(f'Trust anchor matches the root of trust: OK')

    app = NDNApp(keychain=keychain)

    # Note: This producer example does not use LVS validator at all
    # Also, the content of keychain is as follows:
    #   /lvs-test2
    #   +->* /lvs-test2/KEY/%5Cs%F8%B5%D9k%D2%D2
    #        +->* /lvs-test2/KEY/%5Cs%F8%B5%D9k%D2%D2/self/v=1647829075409
    # --
    #   /lvs-test2/admin/ndn
    #   +->* /lvs-test2/admin/ndn/KEY/z%C7%D2%B0%22%FB%D0%F3
    #        +->  /lvs-test2/admin/ndn/KEY/z%C7%D2%B0%22%FB%D0%F3/self/v=1647828984149
    #        +->* /lvs-test2/admin/ndn/KEY/z%C7%D2%B0%22%FB%D0%F3/lvs-test2/v=1647829580626
    # --
    # * /lvs-test2/author/xinyu
    #   +->* /lvs-test2/author/xinyu/KEY/%18%F9%A7CP%F6%BD%1B
    #        +->  /lvs-test2/author/xinyu/KEY/%18%F9%A7CP%F6%BD%1B/self/v=1647828975217
    #        +->* /lvs-test2/author/xinyu/KEY/%18%F9%A7CP%F6%BD%1B/ndn/v=1647829957196


    @app.route('/lvs-test2/article/vincent/hello')
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        content = "Hello,".encode()
        data_name = name + [Component.from_version(timestamp())]
        sign_cert_name = checker.suggest(data_name, app.keychain)
        print(f'        Suggested signing cert: {Name.to_str(sign_cert_name)}')
        app.put_data(data_name, content=content, freshness_period=10000, cert=sign_cert_name)
        print(f'<< D: {Name.to_str(data_name)}')
        print(f'Content: {content.decode()}')
        print('')

    @app.route('/lvs-test2/article/vincent/world')
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        content = "world!".encode()
        data_name = name + [Component.from_version(timestamp())]
        sign_cert_name = checker.suggest(data_name, app.keychain)
        print(f'        Suggested signing cert: {Name.to_str(sign_cert_name)}')
        app.put_data(data_name, content=content, freshness_period=10000, cert=sign_cert_name)
        print(f'<< D: {Name.to_str(data_name)}')
        print(f'Content: {content.decode()}')
        print('')

    @app.route(trust_anchor.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(trust_anchor.data)
        print(f'<< D: {Name.to_str(trust_anchor.name)}')
        print('')

    @app.route(admin_cert.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(admin_cert.data)
        print(f'<< D: {Name.to_str(admin_cert.name)}')
        print('')

    @app.route(author_cert.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(author_cert.data)
        print(f'<< D: {Name.to_str(author_cert.name)}')
        print('')

    print('Start serving ...')
    app.run_forever()


if __name__ == '__main__':
    main()