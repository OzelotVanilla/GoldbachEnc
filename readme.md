GoldbachEnc
====

A public-key encrypt algorithm that inspired by Goldbach Conjecture.

Requirement
----

* Python 3.10 or later.
* Python `rsa` module.

Structure
----

`main.py`: Contains an example of using the algorithm.

`cryptfunc.py`: Function that do the encrypt/decrypt.

`mathfunc.py`: Function which related to generation of key.

`simulation_entities.py`: Example purpose, for simulate two users.

`str_manip.py`: Contains tool to manipulate the string.

How to Run
----

1. Download the file in this project, all into a folder.
2. Run file `main.py`. If using terminal, use `python ./main.py`.

> Notice: If you get some error like `python` is not recognized,
> please search online to solve this problem
> (like, install some tools such as "python is python3").

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
To confuse the attacker, the inverse should add $n$ until it is greater than $k$
(this is used to ensure that plaintext multiply $a^{-1}$ will be greater than $k$).

Lastly, considered the bit length of $n$, and generate $x$ as **public key**
(or, we call it `less_than_n_bit`). $x$ will be chose randomly from $10$ to the
bit length of $n - 1$.

> #### Why need `less_than_n_bit`
>
> Since it is impossible to directly send $n$ through network.
> However, if the plaintext is longer than $n$, the mod operation will not work.
>
> So, this one only show the attacker the fact that $n$ is a number bigger than
> some number (`2 ** less_than_n_bit`), and less than $k$.
> It is still hard to check which number is $n$ (decomposite $k$ is different).

Now the public and private key generation is finished:

* **public key**: $a^{-1}$, $b^{-1}$, $k$, $x$.
* **private key**: $a$, $b$, $n$.

Their relationship is:

* $a + b = n$, while $n$ is an even number.
* $a$ and $n$ coprime.
* $b$ and $n$ coprime.
* $k$ is $n$ multiply by several prime (which is not comprime with $n$).
* $a^{-1} > k$ and $b^{-1} > k$.

### Encryption

This algorithm is considered a block cipher.

Assume that the internal minimal unit of the string will be `byte`.

Each time, extract `less_than_n_bit` number of bits from string,
let these bits considered as a number $m$.
Use $c = m \cdot a^{-1} \; \mathrm{mod} \; k$ as the encrypted text.

When the string is *exhausted* (you cannot extract exact number of bits,
since there is not enough bits in the string), encrypt it, send, and stop.

> #### What need to be done to solve leading zeros in bit representation ?
>
> Add always a leading one before all the bits (add to `m`),
> and remove that one when decrypting.


### Decryption

From the encrypted message, each time, pop a number from head, let it be $c$.
Then, the decrypt approach is
$m = (c \;  \mathrm{mod} \; n) \cdot a \; \mathrm{mod} \; k$
to calculate the original text.

> Do not forget the algorithm once add one leading one.
> This leading one is removed after $m$ is calculated.

Specialty and Strength
----

This algorithm use **multiplication** instead of **power function** (e.g. in *RSA*),
so the data is not enlarged too much, and the computation could be done faster.

Since the big number is considered hard to decompose into prime factors,
the public key can be considered safe.
Even the attacker decomposes it into primes,
they must also try the correct combination to get $n$
(since $n$ is an even number, and has possibility to be decomposed into different numbers).
If the prime multiplied with $k$ is ranged from small to big number,
it will make it even harder to get $n$.

Omake
----

Have you seen the `main.py`,
and see the name *Featherine Augustus Aurora* and *Beatrice Castiglioni* ?
Are you interested in who are they ?

They are the characters from a game
[*Umineko When They Cry*](https://en.wikipedia.org/wiki/Umineko_When_They_Cry)
(うみねこの<span style="color: red">な</span>く頃に).
This is a game about the magic, detective, illusion,
and the mystery story created by the witch of the gold.
If you have time, you can dive into this game, I hope you can find it fun!

Happy coding, happy gaming, hope you have a nice day.