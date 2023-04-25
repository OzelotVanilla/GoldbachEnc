GoldbachEnc
====

A public-key encrypt algorithm that inspired by Goldbach Conjecture.

Requirement
----

* Python 3.10 or later.
* Python `rsa` module

Structure
----

`main.py`: Contains an example of using the algorithm.

`cryptfunc.py`: Function that do the encrypt/decrypt.

`mathfunc.py`: Function which related to generation of key.

`simulation_entities.py`: Example purpose, for simulate two users.

`str_manip.py`: Contains tool to manipulate the string.

Mechanism of Encryption/Decryption
----

For the [Goldbach Conjecture](https://en.wikipedia.org/wiki/Goldbach%27s_conjecture),
it says that for a even number, it can be written in the form of two primes.

### Key Generation

This algorithm assumes this is correct, and first generate two prime $a$ and $b$.
Then let $n = a + b$, and ensure that $a$ and $n$ coprime, $b$ and $n$ coprime.
If not, regenerate $a$ and $b$.
This is the place that Goldbach Conjecture inspire this encrypt algorithm.

Then, generate one of the **public key** $k$, which will be the multiplication of primes 
$k = n \cdot p_1 \cdot ... \cdot p_n \ (p\in P, p \ne n)$.

Then, generate the inverse of $a$ and $b$ under $\mathrm{mod} \; n$ as **public key**.
Since the coprime relationship, the inverse is guaranteed to be existed.
To confuse the attacker, the inverse should add $n$ until it is greater than $k$.

Lastly, considered the bit length of $n$, and generate $x$ as **public key**
(or, we call it `less_than_n_bit`). $x$ will be chose randomly from $10$ to the
bit length of $n - 1$.

### Encryption

This algorithm is considered a block cipher.

Assume that the internal minimal unit of the string will be `byte`.

Each time, extract the exactly `less_than_n_bit` number of bits from string,
let these bits considered as a number $m$.
Use $c=m \cdot a^{-1} \; \% \; k$ as the encrypted text.

When the string is *exhausted* (you cannot extract exact number of bits,
since there is not enough bits in the string), encrypt it, send, and stop.

> #### Why we do not add zeros ?
>
> Since the string will be built afterward byte by byte.