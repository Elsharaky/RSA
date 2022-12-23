from random import randint
def _is_prime(n: int, k: int = 128) -> bool:
    '''
    Check if the the provided number is prime or composite using Miller–Rabin primality test.
    params:
        n -> number to check if prime or composite.
        k -> number of iterations of the test.
    '''
    if n == 2 or n == 3:
        return True
    if n <= 0 or not n & 1:
        return False
    
    s = 0
    d = n - 1

    while not d & 1:
        s += 1
        d >>= 1
    
    for _ in range(k):
        a = randint(1,n-1)
        x = pow(a,d,n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x,2,n)
                if x == n - 1:
                    return True
                j += 1
            if x != n - 1:
                return False
    return True

def generate_prime(length: int = 1024) -> int:
    '''
    Generate a prime number with number of bits equals the length param.
    By generating a random number and check if it's a prime or not and when find a prime number the function returns it. 
    '''
    while True:
      num = randint(pow(2,length-1),pow(2,length))
      if _is_prime(num):
         return num


