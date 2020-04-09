=========
WeasySign
=========

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
* A special thanks to the super elegant asn1crypto library: https://github.com/wbond/asn1crypto

-------------
Documentation
-------------
WeasySign makes use of WeasyPrints' finisher hook. WeasyPrint allows users to
pass a finishing function to Document.write_pdf() for post-processing of the
PDF file.

.. code:: python

  from weasyprint import HTML
  from weasysign import factory

  document = HTML.render()
  # To sign the pdf with a self-signed certificate:
  signer = factory('selfsigned', cert='/bla/cert.crt', private_key='/bla/cert.key')
  document.write_pdf(target='/tmp/my-self-signed-doc.pdf', finisher=signer)

  # To sign the pdf using GlobalSigns DSS API:
  subject_dn = {'subject_dn': {
    "common_name": "Dunder Mifflin Paper Company, Inc.",
    "organizational_unit": [
      "Angela Martin",
      "Accounting"
    ]
  }}
  signer = factory('globalsign', cfg_file='/bla/globalsign_config.ini', subject_dn=subject_dn)
  document.write_pdf(target='/tmp/my-digitally-signed-doc.pdf', finisher=signer)

The configuration file for the GlobalSign signer is a simple .ini file:

.. code:: ini

  [SSL]
  certfile = /some/dir/signatures_globalsign.crt
  keyfile = /some/dir/signatures_globalsign.key
  keypass = Pam is the office mattress
  [API]
  url = https://emea.api.dss.globalsign.com:8443
  # The endpoint will be appended to the url:
  endpoint = /v2
  api_key = **********
  api_secret = ************************

The private key password can alternatively be passed to the factory constructor:

.. code:: python

  signer = factory('globalsign', cfg_file='/bla/globalsign_config.ini', keypass="Pam is the office mattress" subject_dn=subject_dn)


