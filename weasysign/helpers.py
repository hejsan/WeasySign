import os
import hashlib
from datetime import datetime
import requests
from weasyprint.pdf import pdf_format


def pkcs11_aligned(data):
    data = ''.join(['%02x' % i for i in data])
    nb = 0x4000 - len(data)
    data = data + '0' * (0x4000 - len(data))
    return data

def write_stream_object(pdf, content):
    """Write a simple stream object.
    :return:
        the object number of the stream object

    """
    assert isinstance(content, bytes)

    object_number = pdf.next_object_number()
    offset, write = pdf._start_writing()
    write(pdf_format('{0} 0 obj\n', object_number))
    write(pdf_format('<<\n /Length {0} \n>>\nstream\n', len(content)))
    write(content)
    write(b'\nendstream\n')
    write(b'endobj\n')

    pdf.new_objects_offsets.append(offset)
    return object_number



def write_signature_placeholder(pdf):
    signature_max_length = 16384*2
    #signature_max_length = 11742
    date = datetime.utcnow()
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')

    byterange_placeholder = b'/ByteRange[0 ********** ********** **********]'
    #content = b'<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached '
    content = b'<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached '
    content += byterange_placeholder
    content += b' /M(D:%b)' % bytes(date.encode('latin1'))  # .$this->_datestring($sigobjid, $this->doc_modification_timestamp);
    content += b' /Contents<' + b'0' * signature_max_length + b'>'
    # This is not needed if it can be read from the signature anyway
    #content += b' /Name(University of Iceland)'  #.$this->_textstring($this->signature_data['info']['Name'], $sigobjid)
    #content += ' /Location(Reykjavík)'.encode('utf-8')  #.$this->_textstring($this->signature_data['info']['Name'], $sigobjid)
    #content += b' /Reason(Digital Signature)'  #.$this->_textstring($this->signature_data['info']['Name'], $sigobjid)
    #content += b' /ContactInfo(Bjarni)'  #.$this->_textstring($this->signature_data['info']['Name'], $sigobjid)

    # TODO: see https://github.com/tecnickcom/TCPDF/blob/master/tcpdf.php#L10299
    content += b' >>'
    pdf.signature_number = pdf.write_new_object(content)
    # Store the byte offset where the signature object starts
    pdf.signature_offset = pdf.new_objects_offsets[-1]

    object_number = pdf.next_object_number()
    signature_rect = b'<</F 132/Type/Annot/Subtype/Widget/Rect[0 0 0 0]/FT/Sig/DR<<>>/T(signature%d)/P 2 0 R/V %d 0 R>>' % (object_number, object_number-1)
    pdf._signature_rect_number = object_number
    params = b''
    #if embedded_files_id is not None:
    params += b' /AcroForm <</Fields[%d 0 R] /SigFlags 3>>' % object_number
    pdf.extend_dict(pdf.catalog, params)
    assert(len(pdf.pages) > 0)
    pdf.extend_dict(pdf.pages[0], b'/Annots [%d 0 R]' % object_number)

    pdf.write_new_object(signature_rect)


import ssl
from requests.adapters import HTTPAdapter


# SSLAdapter is a wrapper around requests.adapters.HTTPAdapter that provides
# a secure context to requests using private/public key cryptography
# enabling you to use your own specified private/public key pair
# to encrypt a session with a server
class SSLAdapter(HTTPAdapter):
    def __init__(self, certfile, keyfile, password=None, *args, **kwargs):
        self._certfile = certfile
        self._keyfile = keyfile
        self._password = password
        return super(self.__class__, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self._certfile,
                                keyfile=self._keyfile,
                                password=self._password)
        kwargs['ssl_context'] = context
        return super(self.__class__, self).init_poolmanager(*args, **kwargs)


import configparser
def get_config(cfg_file):
    config = configparser.ConfigParser()
    config.read(cfg_file)
    return config['SSL'], config['API']


def get_session(url, certfile, keyfile, password=None):
    session = requests.Session()
    adapter = SSLAdapter(certfile, keyfile, password)
    session.mount(url, adapter)
    #session.verify = False
    return session


class APIError(Exception):
    pass


# Testing
subject_dn = {'subject_dn': {
  "common_name": "University of Iceland",
  "country": "IS",
  "state": "Iceland",
  "locality": "Iceland",
  "street_address": "Sæmundargötu 4",
  "organization": "University of Iceland",
  "organizational_unit": [
    "Operations",
    "Development"
  ],
  "email": "b@hi.is",
  "jurisdiction_of_incorporation_locality_name": "Iceland",
  "jurisdiction_of_incorporation_state_or_province_name": "Iceland",
  "jurisdiction_of_incorporation_country_name": "Iceland",
  "business_category": "Education",
  "extra_attributes": [
    {
      "type": "2.5.4.4",
      "value": "Surname"
    }
  ]
}}
subject_dn_ = {"subject_dn": {
  #"common_name": "Háskóli Íslands",
  "organizational_unit": [
    "Operations",
    "Development"
  ]
}}


# get_digest extracts all contents of the pdf excluding the actual part
# that will contain the digest signature
def get_digest(pdf):
    byterange_placeholder = b'/ByteRange[0 ********** ********** **********]'
    byterange_string = '/ByteRange[0 {} {} {}]'
    byterange = [0, 0, 0, 0]
    # TODO: allow variable length according to method
    signature_max_length = 16384*2
    assert pdf.signature_offset
    fileobj = pdf.fileobj
    fileobj.seek(pdf.signature_offset)
    next(fileobj)  # Skip to object content line
    # 153 is the length until the Contents part
    byterange[1] = fileobj.tell() + 153
    byterange[2] = byterange[1] + signature_max_length + 2
    byterange[3] = fileobj.getbuffer().nbytes - byterange[2]
    byterange_final = pdf_format(byterange_string, byterange[1], byterange[2], byterange[3])
    byterange_final = byterange_final.ljust(46, b' ')
    fileobj.seek(69, os.SEEK_CUR)
    fileobj.write(byterange_final)
    fileobj.seek(39, os.SEEK_CUR)
    buf = fileobj.getbuffer()

    # This is to write the digest to a file for debugging
    #with open('/tmp/digest.txt', "wb") as digest_file:
        #digest_file.write(buf[0:byterange[1]])
        #digest_file.write(buf[byterange[2]:byterange[2]+byterange[3]])
    hasher = hashlib.sha256()
    hasher.update(buf[0:byterange[1]])
    hasher.update(buf[byterange[2]:byterange[2]+byterange[3]])
    # hasher maps a variable length bytestring to a fixed length bytestring
    return hasher.digest()

