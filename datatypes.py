import sys

class DoubleDict(dict):
    '''
    Allows search both as key:value and value:key
    '''
    
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.mirrored = {v:k for k,v in self.items()}
    
    def __getitem__(self, *args, **kwargs):
        try:
            return dict.__getitem__(self, *args, **kwargs)
        except KeyError:
            try:
                return self.mirrored.__getitem__(*args, **kwargs)
            except KeyError:
                print('Unknown type', *args, **kwargs)
                sys.exit(1)

                
class FlaggedDict(dict):
    '''
    Recognize if dict was changed
    '''
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.__old_vals = self.values()
        
    def has_changed(self):
        return self.values() != self.__old_vals
    
    def store(self):
        self.__old_vals = self.values()
        
