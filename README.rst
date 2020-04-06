==========
WeasySign
==========

**Digital Signatures for WeasyPrint**

WeasySign is a small library intended to be a high level (as in simple to use)
library for digitally signing pdf's generated with the WeasyPrint PDF library.

WeasySign currently has adapters for using Self-Signed Certificates
and using Globalsigns' DSS API.

This initial version is _very_ much a work made in a stream of consciousness
as a reaction to Covid-19 forcing staff to work from home, making printing
and hand-signing documents impractical. Therefore you should not expect the 
code to be either elegant nor efficient quite yet. For example the helpers.py
is a mess of various functions that should probably be made into a better 
structure.

WeasySign was written for the University of Iceland (https://www.hi.is).


* Free software: BSD licensed
* Python 3.5+
* WeasyPrint: https://github.com/Kozea/WeasyPrint
* Globalsign DSS API Documentation: https://www.globalsign.com/en/resources/apis/api-documentation/digital-signing-service-api-documentation.html
* Source code and issue tracker: https://github.com/hejsan/WeasySign
* Documentation: TBD
* Tests: TBD

