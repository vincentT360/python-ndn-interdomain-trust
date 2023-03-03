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

### Running the App
1. Make sure nfd is started
2. For whatever domain you want to run the entities on execute ```python consumer.py``` or ```python producer.py``` for the corresponding domain.
    * E.g ```python consumer-interdomain-lvstest.py``` and ```python producer-interdomain-lvstest2.py```