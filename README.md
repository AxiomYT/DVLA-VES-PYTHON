# DVLA-VES-PYTHON
DVLA.PY exists to serve as a convenient programmatic way to access the UK's DVLA VES API

The DVLA Vehicle Enquiry Service API is a RESTful service that provides vehicle details 
of a specified vehicle. It uses the vehicle registration number as input to search and 
provide details of the vehicle. The response data is provided in JSON format.

API Keys are required and can be acquired from: 
https://register-for-ves.driver-vehicle-licensing.api.gov.uk/ 

The key itself is stored on the device, in the form of a "keyring" entry. This is 
a pip package that takes in passwords / credentials, and communicates with the
host machine in order to store this string securely. Details about the project
can be found here:
https://pypi.org/project/keyring/

The registration is validated before being compiled and sent as a HTTP request, this is
done this way in order to not waste usage of the API key. There is a rate limit, 
however the exact number is obfuscated, best not push this too far.

The response is validated and checked, then displayed in both a "Raw" JSON response,
and an easy to read summary which expands on that further.
