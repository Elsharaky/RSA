# RSA

This repo for RSA Encryption and Decryption.

## RSA Essentials

- Pick (P,Q) two prime numbers.
- Calculate N &rarr; P * Q.
- Calculate $\phi$(N) &rarr; (P-1) * (Q-1).
- Pick E
  - 1 < E < $\phi$(N).
  - E is co-prime with N , $\phi$(N).
- Pick D
  - D*E (mod $\phi$(N)) = 1.
---

## RSA Encryption and Decryption

Encryption pairs are (E,N) &rarr; Public.

Decryption pairs are (D,N) &rarr; Private.

### Encryption

C = $P^{E}$ (mod N).

### Decryption

P = $C^{D}$ (mod N).

