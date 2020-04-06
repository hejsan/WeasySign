import requests
import base64
import time
import hashlib
from .helpers import get_config, get_session, write_signature_placeholder, APIError, subject_dn_ as default_subject_dn, get_digest, pkcs11_aligned, write_stream_object
from .selfsigned import cert2asn


import datetime
from asn1crypto import cms, algos, core, pem, tsp, x509, util, ocsp, pdf
from cryptography import x509 as cryptox509
from cryptography.x509 import ocsp as cryptoocsp
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.backends import default_backend


class GlobalSignSigner:

    def __init__(self, cfg_file, subject_dn=None):
        self._ssl, self._api = get_config(cfg_file)
        self._url = self._api.get('url') + self._api.get('endpoint')
        self._subject_dn = subject_dn or default_subject_dn
        self._login_url = self._url + '/login'
        self._certificate_path_url = self._url + '/certificate_path'
        self._quota_signatures = self._url + '/quotas/signatures'
        self._identity_url = self._url + '/identity'
        self._validation_policy_url = self._url + '/validationpolicy'
        self._quota_signatures_url = self._url + '/quotas/signatures'
        self._signature_url = self._url + '/identity/{id}/sign/{digest}'
        self._timestamp_url = self._url + '/timestamp/{digest}'
        self._trustchain_url = self._url + '/trustchain'

    def write_signature_placeholder(self, pdf):
        return write_signature_placeholder(pdf)

    def write_signature(self, pdf):
        # Start a secure session so we don't have to set the same headers in every call
        s = get_session(self._api.get('url'), **self._ssl)
        s.headers.update({'Content-Type': 'application/json;charset=utf-8', 'Accept-Encoding': None})
        private_key = None
        with open(self._ssl['keyfile'], "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=self._ssl['password'].encode('utf-8'),
                backend=default_backend()
            )

        org_cert = None
        with open(self._ssl['certfile'], "rb") as cert_file:
            org_cert = cryptox509.load_pem_x509_certificate(
                cert_file.read(), 
                default_backend()
            )


        # Login in and get the access token
        r = s.post(self._login_url,
            json={'api_key': self._api.get('api_key'), 'api_secret': self._api.get('api_secret')},
        )
        if r.status_code != 200:
            raise APIError('Cannot login: {}\n{}'.format(r.status_code, r.json()))
        token = r.json()['access_token']
        # Add an Authorization header with the access token
        s.headers.update({"Authorization": "Bearer {}".format(token)})

        r = s.post(self._identity_url, json=self._subject_dn)
        if r.status_code != 200:
            raise APIError('Cannot retrieve the id used to sign the identity requests: {}\n{}'.format(r.status_code, r.json()))
        identity = r.json()
        id = identity['id']
        signing_cert = identity['signing_cert']
        self._signing_ocsp_response_raw = base64.b64decode(identity['ocsp_response'].encode('ascii'))

        r = s.get(self._trustchain_url)
        if r.status_code != 200:
            raise APIError('Cannot retrieve the trustchain: {}\n{}'.format(r.status_code, r.json()))
        self._revocation_info = r.json()['ocsp_revocation_info']
        self._trustchain_ocsp_revocation_info_raw = [base64.b64decode(o.encode('ascii')) for o in self._revocation_info]


        self._dss_trustchain = []
        self._trustchain_raw = [c.encode('ascii') for c in r.json()['trustchain']]
        self._trustchain = []
        for c in self._trustchain_raw:
            self._dss_trustchain.append(
                cryptox509.load_pem_x509_certificate(
                    c, 
                    default_backend()
                )
            )

        # Fetch the path to the ca (certificate authority)
        r = s.get(self._certificate_path_url)
        if r.status_code != 200:
            raise APIError('Cannot retrieve the certificate path: {}\n{}'.format(r.status_code, r.json()))
        ca = r.json()['path']
        self._trustchain.append(
            cryptox509.load_pem_x509_certificate(
                ca.encode('ascii'), 
                default_backend()
            )
        )

        response = ocsp.OCSPResponse.load(self._signing_ocsp_response_raw)
        self._ocsp_response = response

        digest = get_digest(pdf)

        self._signing_cert_raw = signing_cert.encode('ascii')
        signing_cert = cryptox509.load_pem_x509_certificate(
            self._signing_cert_raw, 
            default_backend()
        )

        # Thw _sign function builds the signature dictionary to be written to the PDF's signature content
        digital_signature = self._sign(None, private_key, signing_cert, self._trustchain, 'sha256', True, digest, None, False, "http://public-qlts.certum.pl/qts-17", identity['id'], s)
        digital_signature = pkcs11_aligned(digital_signature)  # ocsp_resp.public_bytes(serialization.Encoding.DER))
        pdf.fileobj.write(digital_signature.encode('ascii'))

        # Long Term Validation (LTV) stuff
        dss_number = pdf.next_object_number()
        certlist_number = dss_number + 1
        ocsplist_number = dss_number + 2
        expected_next_object_number = dss_number + 3
        
        params = b' /Version/1.7 /AcroForm <</Fields[%d 0 R] /SigFlags 3>>/DSS %d 0 R /Extensions<</ESIC <</BaseVersion/1.7/ExtensionLevel 1>>>>' % (pdf._signature_rect_number, dss_number)
        pdf.extend_dict(pdf.catalog, params)

        dss = b'<</Certs %d 0 R/OCSPs %d 0 R>>' % (certlist_number, ocsplist_number)
        pdf.write_new_object(dss)
        
        first_cert_number = dss_number + 3
        # The +1 is because the signing cert is not in the trustchain list
        cert_list_numbers = [first_cert_number + n for n in range(0, len(self._trustchain_raw) + 1)]
        cert_list = b'['
        for n in cert_list_numbers:
            cert_list += b'%d 0 R ' % n
        cert_list += b']'
        pdf.write_new_object(cert_list)

        first_ocsp_number = first_cert_number + len(cert_list_numbers) 
        ocsp_list_numbers = [first_ocsp_number + n for n in range(0, len(self._trustchain_ocsp_revocation_info_raw) + 1)]
        ocsp_list = b'['
        for n in ocsp_list_numbers:
            ocsp_list += b'%d 0 R ' % n
        ocsp_list += b']'
        pdf.write_new_object(ocsp_list)


        assert pdf.next_object_number() == expected_next_object_number


        cert_numbers = []
        for c in self._dss_trustchain:
            cert_numbers.append(write_stream_object(pdf, c.public_bytes(serialization.Encoding.DER)))
        cert_numbers.append(write_stream_object(pdf, signing_cert.public_bytes(serialization.Encoding.DER)))
        assert cert_numbers == cert_list_numbers

        ocsp_numbers = []
        for o in self._trustchain_ocsp_revocation_info_raw:
            ocsp_numbers.append(write_stream_object(pdf, o))
        ocsp_numbers.append(write_stream_object(pdf, self._signing_ocsp_response_raw))
        assert ocsp_numbers == ocsp_list_numbers

        self._document_timestamp(pdf, s)

    
    def _sign(self, datau, key, signing_cert, trustchain, hashalgo, attrs=True, signed_value=None, hsm=None, pss=False, timestampurl=None, identity=None, s=None):
        if signed_value is None:
            signed_value = getattr(hashlib, hashalgo)(datau).digest()
        signed_time = datetime.datetime.now(tz=util.timezone.utc)

        if hsm is not None:
            keyid, cert = hsm.certificate()
            cert = cert2asn(cert, False)
            trustchain = []
        else:
            signing_cert = cert2asn(signing_cert)

        certificates = []
        for c in trustchain:
            certificates.append(cert2asn(c))
        certificates.append(signing_cert)

        signer = {
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': signing_cert.issuer,
                    'serial_number': signing_cert.serial_number,
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo}),
            'signature': signed_value,
        }
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'})

        if attrs:
            if attrs is True:
                signer['signed_attrs'] = [
                    cms.CMSAttribute({
                        'type': cms.CMSAttributeType('content_type'),
                        'values': ('data',),
                    }),
                    cms.CMSAttribute({
                        'type': cms.CMSAttributeType('message_digest'),
                        'values': (signed_value,),
                    }),
                    #cms.CMSAttribute({
                        #'type': cms.CMSAttributeType('signing_time'),
                        #'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
                    #}),
                ]
            else:
                signer['signed_attrs'] = attrs

        # TODO: Keep it all in one loop
        ocsp_revocation = []
        ocsp_revocation.append(
            cms.RevocationInfoChoice({
                'other': cms.OtherRevocationInfoFormat({
                    'other_rev_info_format': cms.OtherRevInfoFormatId('ocsp_response'),
                    'other_rev_info': self._ocsp_response
                })
            })
        )

        # TODO: Don't need this because I have a DSS now
        #for rev in self._revocation_info:
            #rev = base64.b64decode(rev)
            #rev = ocsp.OCSPResponse.load(rev)
            #ocsp_revocation.append(
                #cms.RevocationInfoChoice({
                    #'other': cms.OtherRevocationInfoFormat({
                        #'other_rev_info_format': cms.OtherRevInfoFormatId('ocsp_response'),
                        #'other_rev_info': rev
                    #})
                #})
            #)


        config = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((
                algos.DigestAlgorithm({'algorithm': hashalgo}),
            )),
            'encap_content_info': {
                'content_type': 'data',
            },
            'certificates': certificates,
            'crls': ocsp_revocation,
            'signer_infos': [
                signer,
            ],
        }
        datas = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(config),
        })
        if attrs:
            tosign = datas['content']['signer_infos'][0]['signed_attrs'].dump()
            tosign = b'\x31' + tosign[1:]
        else:
            tosign = datau

        tosign = getattr(hashlib, hashalgo)(tosign).digest()
        # Fetch the actual signature
        r = s.get(self._signature_url.format(id=identity, digest=tosign.hex().upper()))
        if r.status_code != 200:
            raise APIError('Cannot retrieve the signature: {}\n{}'.format(r.status_code, r.json()))
        signed_value_signature = r.json()['signature']
        signed_value_signature = bytes.fromhex(signed_value_signature)
        signed_value = getattr(hashlib, hashalgo)(signed_value_signature).digest()
        datas['content']['signer_infos'][0]['signature'] = signed_value_signature

        # Use globalsigns timestamp
        # TODO: uncomment next 17 lines  to have timestamped signature
        r = s.get(self._timestamp_url.format(digest=signed_value.hex().upper()))
        if r.status_code != 200:
            raise APIError('Cannot retrieve the timestamp: {}\n{}'.format(r.status_code, r.json()))
        timestamp_token = r.json()['token']
        timestamp_token = timestamp_token.encode('ascii')
        timestamp_token = base64.b64decode(timestamp_token)
        tsp_dict = cms.ContentInfo.load(timestamp_token)
        tsp_attrs = [
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('signature_time_stamp_token'),
                'values': cms.SetOfContentInfo([
                    cms.ContentInfo({
                        'content_type': cms.ContentType('signed_data'),
                        'content': tsp_dict['content'],
                    })
                ])
            })
        ]
        datas['content']['signer_infos'][0]['unsigned_attrs'] = tsp_attrs


        # TODO: OCSP stuff - probably not necessary since we have a DSS

        #ocsp_seq = pdf.SequenceOfOCSPResponse((self._ocsp_response,))
        #ocsp_arc = pdf.RevocationInfoArchival({'ocsp': ocsp_seq})
        #revocation_info = pdf.SetOfRevocationInfoArchival()
        #revocation_info.append(ocsp_arc)
        #self._ocsp_response
        #ocsp_attribute = cms.CMSAttribute({  # basic_ocsp_response
            #'type': cms.CMSAttributeType('adobe_revocation_info_archival'),
            #'values': pdf.SetOfRevocationInfoArchival([
                #pdf.RevocationInfoArchival({
                    #'ocsp': pdf.SequenceOfOCSPResponse(self._ocsp_response)
                #})#cert2asn(ocsp_resp.public_bytes(serialization.Encoding.DER), False)
            #])
        #}),
        #datas['content']['signer_infos'][0]['unsigned_attrs'].append(ocsp_attribute)

        return datas.dump()


    def _document_timestamp(self, pdf, session):
        from weasyprint.pdf import pdf_format
        import os

        byterange_placeholder = b'/ByteRange[0 ********** ********** **********]'
        byterange_string = '/ByteRange[0 {} {} {}]'
        byterange = [0, 0, 0, 0]

        tsp = b'<</Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /Contents <'
        len_to_content = len(tsp)
        tsp += b'0' * 16384 + b'>'
        tsp += byterange_placeholder + b'>>'

        tsp_number = pdf.write_new_object(tsp)
        # Store the byte offset where the timestamp object starts
        tsp_offset = pdf.new_objects_offsets[-1]
        pdf.finish()

        fileobj = pdf.fileobj
        fileobj.seek(tsp_offset)
        next(fileobj)  # Skip to object content line
        # 153 is the length until the Contents part
        byterange[1] = fileobj.tell() + len_to_content - 1  # -1 to exclude the <
        byterange[2] = byterange[1] + 16384 + 2
        byterange[3] = fileobj.getbuffer().nbytes - byterange[2]
        byterange_final = pdf_format(byterange_string, byterange[1], byterange[2], byterange[3])
        byterange_final = byterange_final.ljust(46, b' ')

        fileobj.seek(len_to_content + 16384 + 1, os.SEEK_CUR)
        fileobj.write(byterange_final)

        tsp_digest = self._hash(pdf, byterange)
        r = session.get(self._timestamp_url.format(digest=tsp_digest.hex().upper()))
        if r.status_code != 200:
            raise APIError('Cannot retrieve the document timestamp: {}\n{}'.format(r.status_code, r.json()))
        timestamp_token = r.json()['token']
        timestamp_token = timestamp_token.encode('ascii')
        timestamp_token = base64.b64decode(timestamp_token)
        #timestamp_token = pkcs11_aligned(timestamp_token)  # ocsp_resp.public_bytes(serialization.Encoding.DER))

        fileobj.seek(tsp_offset)
        next(fileobj)  # Skip to object content line
        fileobj.seek(len_to_content, os.SEEK_CUR)
        fileobj.write(timestamp_token)

        #tsp_dict = cms.ContentInfo.load(timestamp_token)
        #tsp_attrs = [
            #cms.CMSAttribute({
                #'type': cms.CMSAttributeType('signature_time_stamp_token'),
                #'values': cms.SetOfContentInfo([
                    #cms.ContentInfo({
                        #'content_type': cms.ContentType('signed_data'),
                        #'content': tsp_dict['content'],  # adb_tsp_ext,  # tiii["time_stamp_token"]["content"],
                    #})
                #])
            #})
        #]
        #datas['content']['signer_infos'][0]['unsigned_attrs'] = tsp_attrs

    def _hash(self, pdf, byterange):
        buf = pdf.fileobj.getbuffer()
        with open('/tmp/digest.txt', "wb") as digest_file:
            digest_file.write(buf[:byterange[1]])
            digest_file.write(buf[byterange[2]:])
        # Get the digest
        hasher = hashlib.sha256()
        hasher.update(buf[:byterange[1]])
        hasher.update(buf[byterange[2]:])
        # hasher maps a variable length bytestring to a fixed length bytestring
        return hasher.digest()

