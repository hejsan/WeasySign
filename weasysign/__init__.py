def factory(provider, **kwargs):
    if provider == 'selfsigned':
        from .selfsigned import SelfSigner
        return SelfSigner(**kwargs)
    elif provider == 'globalsign':
        from .globalsign import GlobalSignSigner
        return GlobalSignSigner(**kwargs)


class BaseSigner:
    def __call__(self, pdf):
        # Add placeholder for the digital signature
        # This is later overwritten after all content has been written
        # and a checksum can be calculated
        self.write_signature_placeholder(pdf)

        pdf.finish(False)

        # This overwrites the signature placeholer
        self.write_signature(pdf)
