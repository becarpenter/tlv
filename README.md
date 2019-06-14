# tlv
Python 3 code for a Type-Length-Value support module.

This repository is for a Python 3 module that provides dumps() and loads() functions for protocols transmitted in a binary type-length-value (TLV) format. It is intended to be used like JSON or CBOR dumps() and loads() functions. However, the first parameter in both function calls is a pattern that describes the TLV wire format. It must be strictly identical in corresponding dumps() and loads().

The pattern format is documented in the python source file - import tlv and do help(tlv.pattern). Of course, help(tlv) is also available.

This code IS NOT INTENDED FOR PRODUCTION USE. See the license and disclaimer in the tlv.py source file.

There's also some toy code for Service Oriented IP (draft-jiang-service-oriented-ip), purely FYI.
