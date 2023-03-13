# CS217b-Intertrust

### Overview

There are 2 domains
- /lvs-test
- /lvs-test2

Entity breakdown
1. ```consumer.py``` and ```producer.py```: Simple consumer/producer entities that do communication within /lvs-test domain. This does intradomain communication.
2. ```consumer-id.py``` and ```producer-id.py```: This is a consumer application who lives in /lvs-test and wants to fetch data from a producer in /lvs-test2. This does interdomain data consumption.
3. ```controller-c.py``` and ```controller-p.py```: This is a controller entity (split into its consuming/producing parts) that lives in /lvs-test domain.
4. ```controller2-p.py```: This is a controller entity that lives in the /lvs-test2 domain.

### Creating the keychain
This keychain needs to be created for each domain (so you do this twice), the below is for domain /lvs-test:

    # Also, the content of keychain is as follows:
    #   /lvs-test
    #   +->* /lvs-test/KEY/%5Cs%F8%B5%D9k%D2%D2
    #        +->* /lvs-test/KEY/%5Cs%F8%B5%D9k%D2%D2/self/v=1647829075409
    # --
    #   /lvs-test/admin/ndn
    #   +->* /lvs-test/admin/ndn/KEY/z%C7%D2%B0%22%FB%D0%F3
    #        +->  /lvs-test/admin/ndn/KEY/z%C7%D2%B0%22%FB%D0%F3/self/v=1647828984149
    #        +->* /lvs-test/admin/ndn/KEY/z%C7%D2%B0%22%FB%D0%F3/lvs-test/v=1647829580626
    # --
    # * /lvs-test/author/xinyu
    #   +->* /lvs-test/author/xinyu/KEY/%18%F9%A7CP%F6%BD%1B
    #        +->  /lvs-test/author/xinyu/KEY/%18%F9%A7CP%F6%BD%1B/self/v=1647828975217
    #        +->* /lvs-test/author/xinyu/KEY/%18%F9%A7CP%F6%BD%1B/ndn/v=1647829957196
 
To create this keychain, execute the following steps in your command line for each domain using ```ndnsec```
You can replace the author name to whatever you want, but make sure you update the code to reflect that. 
This example is for domain /lvs-test2.
```
ndnsec key-gen /lvs-test2

ndnsec key-gen /lvs-test2/admin/ndn
ndnsec sign-req /lvs-test2/admin/ndn > lt2AdminNdn.csr
ndnsec cert-gen -s /lvs-test2 -i lvs-test2 -r lt2AdminNdn.csr > lt2AdminNdn.ndncert
ndnsec cert-install lt2AdminNdn.ndncert

ndnsec key-gen /lvs-test2/author/vincent
ndnsec sign-req /lvs-test2/author/vincent > lt2AuthorVince.csr
ndnsec cert-gen -s /lvs-test2/admin/ndn -i ndn -r lt2AuthorVince.csr > lt2AuthorVince.ndncert
ndnsec cert-install lt2AuthorVince.ndncert
```

### Running the Interdomain Example
1. Make sure nfd is started
2. First, you need to generate the PoR, run ```controller-c.py``` and ```controller2-p.py```
    * This makes the controller of the /lvs-test domain fetch the trust anchor of the /lvs-test2 domain
    * After fetching, it will also create and store the PoR certificate
    * Note: When creating a PoR, you will need to modify  ```controller-p.py``` line 22 to update to the new PoR
3. Now, you can run the consumer and producer apps, run ```consumer-id.py``` and ```producer-id.py``` and ```controller-p.py```
    * This is a consumer living in /lvs-test who will fetch data from /lvs-test2 while using the PoR to validate
    * The consumer application needs to fetch the PoR from the controller, hence we run ```controller-p.py``` too.

Note: Prefix interest does not seem to work, so when a PoR is created, you need to change the version number on line 136 of cascade_checker when fetching it

Note: cascade_validator, keychainsqlite3, security_v2, validator are designed to replace the existing versions in the python-ndn library in order for this to work