from pyasn1.type import univ , namedtype

class RSAPubkey(univ.Sequence):

    '''
    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,   -- e
    }
    '''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus',univ.Integer()),
        namedtype.NamedType('publicExponent',univ.Integer())
    )


class RSAPrivKey(univ.Sequence):

    '''
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent    INTEGER,  -- d
        prime1    INTEGER,  -- p
        prime2    INTEGER,  -- q
        exponent1    INTEGER,  -- d mod (p -1)
        exponent2    INTEGER,  -- d mod (q -1)
        coefficient    INTEGER,  -- (inverse of q) mod p
    }
    '''

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version',univ.Integer()),
        namedtype.NamedType('modulus',univ.Integer()),
        namedtype.NamedType('publicExponent',univ.Integer()),
        namedtype.NamedType('privateExponent',univ.Integer()),
        namedtype.NamedType('prime1',univ.Integer()),
        namedtype.NamedType('prime2',univ.Integer()),
        namedtype.NamedType('exponent1',univ.Integer()),
        namedtype.NamedType('exponent2',univ.Integer()),
        namedtype.NamedType('coefficient',univ.Integer())
    )



