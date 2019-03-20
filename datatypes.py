
class DoubleDict(dict):
    '''
    Allows search both as key:value and value:key
    '''

    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.mirrored = {v: k for k, v in self.items()}

    def __getitem__(self, *args, **kwargs):
        try:
            return dict.__getitem__(self, *args, **kwargs)
        except KeyError:
            return self.mirrored.__getitem__(*args, **kwargs)
