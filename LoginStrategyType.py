class LoginStrategyType(object):
    def name(self):
        raise NotImplementedError()
    
    def check_preconditions(self):
        return (True, None) # (success, message)

    def login(self):
        raise NotImplementedError()

    def status(self):
        raise NotImplementedError()

    def logout(self):
        raise NotImplementedError()

