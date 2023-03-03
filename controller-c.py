#Controller consumer entity living in /lvs-test domain
#It handles PoR creation

"""
Goals

1. Have controller 1 authenticate controller 2

2. Have controller 1 fetch trust anchor for domain 2 from controller 2
- Controller 1 expresses an interest

3. Have controller 1 sign it and store it as PoR

"""