def factory(provider, **kwargs):
    if provider == 'selfsigned':
        from .selfsigned import SelfSigner
        return SelfSigner(**kwargs)
    elif provider == 'globalsign':
        from .globalsign import GlobalSignSigner
        return GlobalSignSigner(**kwargs)
