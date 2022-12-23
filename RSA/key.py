from prime import generate_prime
from random import randint
from os.path import exists

class NoPublicKeyError(Exception):
    pass
class NoPrivateKeyError(Exception):
    pass

class RSA_Key:
    def __init__(self) -> None:
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.e = None
        self.d = None
        self.exp1 = None
        self.exp2 = None
        self.coef = None
    @classmethod
    def gcd(cls,n: int, m: int) -> int:
        if m == 0:
            return n
        return cls.gcd(m, n % m)
    
    @staticmethod
    def eea(r0,r1):
        s0 , s1 = 1 , 0
        t0 , t1 = 0 , 1
        # swap the two numbers if the second one is greater than the first one.
        if r1 > r0:
            r0 , r1 = r1 , r0
        x = r0
        while r1:
            q = (r0 // r1) # compute the quotient
            # put r1 in r0 and compute the next r and put it in r1
            r0 , r1 = r1 , r0 - q * r1
            # put s1 in s0 and compute the next s and put it in s1
            s0 , s1 = s1 , s0 - q * s1
            # put t1 in t0 and compute the next t and put it in t1
            t0 , t1 = t1 , t0 - q * t1

        # r0 -> GCD
        # s0 -> s
        # t0 -> t
        return t0 % x      # return t0 % the initial r0 to get positive value (for Modular Multiplication Inverse).

    def generate_public_key(self,length: int = 512) -> None:
        self.p = generate_prime(length)
        self.q = generate_prime(length)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.coef = self.eea(self.p,self.q)

        while 1:
            self.e = randint(pow(2,length-1),pow(2,length))
            if self.gcd(self.e,self.phi) == 1:
                break
        
    
    def generate_private_key(self,length: int = 1024) -> None:
        if self.e is None or self.n is None or self.phi is None:
            raise NoPublicKeyError('There is no public key to generate private key!')
        
        self.d = self.eea(self.e,self.phi)
        self.exp1 = self.d % (self.p - 1)
        self.exp2 = self.d % (self.q - 1)

    def save_public_key(self,filename: str,method: str = 'PEM') -> None:
        if self.e is None or self.n is None:
            raise NoPublicKeyError('There is no public key to save!')

        if method != 'DER' and method != 'PEM':
            raise ValueError('There is no such method to save the key!')
        
        from asn1 import RSAPubkey
        from pyasn1.codec.der import encoder
        from base64 import b64encode

        pubk = RSAPubkey()
        pubk.setComponentByName('modulus',self.n)
        pubk.setComponentByName('publicExponent',self.e)

        der_encoded = encoder.encode(pubk)
        if method == 'DER':
            if not exists(filename):
                with open(filename,'wb') as file:
                    file.write(der_encoded)
            else:
                raise FileExistsError('File already exists!')
        
        elif method == 'PEM':
            if not exists(filename):
                start = b'-----BEGIN RSA PUBLIC KEY-----\n'
                end = b'-----END RSA PUBLIC KEY-----'
                content = b64encode(der_encoded)

                with open(filename,'wb') as file:
                    file.write(start)
                    for i in range(0,len(content),64):
                        file.write(content[i:i+64]+b'\n')
                    file.write(end)
            else:
                raise FileExistsError('File already exists!')

    
    def save_private_key(self,filename: str,method: str = 'PEM') -> None:
        if self.d is None or self.n is None:
            raise NoPublicKeyError('There is no private key to save!')
        if method != 'DER' and method != 'PEM':
            raise ValueError('There is no such method to save the key!')

        from asn1 import RSAPrivKey
        from pyasn1.codec.der import encoder
        from base64 import b64encode
        
        prvk = RSAPrivKey()
        prvk.setComponentByName('version',0)
        prvk.setComponentByName('modulus',self.n)
        prvk.setComponentByName('publicExponent',self.e)
        prvk.setComponentByName('privateExponent',self.d)
        prvk.setComponentByName('prime1',self.p)
        prvk.setComponentByName('prime2',self.q)
        prvk.setComponentByName('exponent1',self.exp1)
        prvk.setComponentByName('exponent2',self.exp2)
        prvk.setComponentByName('coefficient',self.coef)

        der_encoded = encoder.encode(prvk)
        if method == 'DER':
            if not exists(filename):
                with open(filename,'wb') as file:
                    file.write(der_encoded)
            else:
                raise FileExistsError('File already exists!')
        
        elif method == 'PEM':
            if not exists(filename):
                start = b'-----BEGIN RSA PRIVATE KEY-----\n'
                end = b'-----END RSA PRIVATE KEY-----'
                content = b64encode(der_encoded)

                with open(filename,'wb') as file:
                    file.write(start)
                    for i in range(0,len(content),64):
                        file.write(content[i:i+64]+b'\n')
                    file.write(end)
            else:
                raise FileExistsError('File already exists!')
    
    def load_public_key(self,filename: str,method: str = 'PEM') -> None:
        if not exists(filename):
            raise FileNotFoundError('There is no such file!')
        if method != 'DER' and method != 'PEM':
            raise ValueError('There is no such method to save the key!')
        
        from pyasn1.codec.der import decoder
        from asn1 import RSAPubkey
        from base64 import b64decode

        if method == 'DER':
            with open(filename,'rb') as file:
                der_encoded = file.read()
                pubk , _ = decoder.decode(der_encoded,asn1Spec=RSAPubkey())
                self.n = int(pubk['modulus'])
                self.e = int(pubk['publicExponent'])
        elif method == 'PEM':
            with open(filename,'rb') as file:
                content = b''.join(file.read().splitlines()[1:-1])
                der_encoded = b64decode(content)
                pubk , _ = decoder.decode(der_encoded,asn1Spec=RSAPubkey())
                self.n = int(pubk['modulus'])
                self.e = int(pubk['publicExponent'])
    
    def load_private_key(self,filename: str,method: str = 'PEM') -> None:
        if not exists(filename):
            raise FileNotFoundError('There is no such file!')
        if method != 'DER' and method != 'PEM':
            raise ValueError('There is no such method to save the key!')
        
        from pyasn1.codec.der import decoder
        from asn1 import RSAPrivKey
        from base64 import b64decode

        if method == 'DER':
            with open(filename,'rb') as file:
                der_encoded = file.read()
                prvk , _ = decoder.decode(der_encoded,asn1Spec=RSAPrivKey())

                self.n = int(prvk['modulus'])
                self.e = int(prvk['publicExponent'])
                self.d = int(prvk['privateExponent'])
                self.p = int(prvk['prime1'])
                self.q = int(prvk['prime2'])
                self.exp1 = int(prvk['exponent1'])
                self.exp2 = int(prvk['exponent2'])
                self.coef = int(prvk['coefficient'])

        elif method == 'PEM':
            with open(filename,'rb') as file:
                content = b''.join(file.read().splitlines()[1:-1])
                der_encoded = b64decode(content)
                prvk , _ = decoder.decode(der_encoded,asn1Spec=RSAPrivKey())
                
                self.n = int(prvk['modulus'])
                self.e = int(prvk['publicExponent'])
                self.d = int(prvk['privateExponent'])
                self.p = int(prvk['prime1'])
                self.q = int(prvk['prime2'])
                self.exp1 = int(prvk['exponent1'])
                self.exp2 = int(prvk['exponent2'])
                self.coef = int(prvk['coefficient'])

