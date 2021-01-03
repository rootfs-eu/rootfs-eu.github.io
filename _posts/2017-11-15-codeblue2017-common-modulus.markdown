---
layout: post
title: CODE BLUE CTF 2017 - Common Modulus series
permalink: codeblue2017-common-modulus
date: '2017-11-15 20:39:00'
author: kmhn
tags:
- writeup
- ctf
- codeblue2017
---



There are 3 challenges in this series, all of which are based on the same problem with varying conditions. Therefore, we'll go through them in increasing order of difficulty and build solutions incrementally.

_N.B. All files related to the problems for these challenges and their solutions are available [here](https://github.com/khalednassar/ctf_writeups/tree/master/codebluectf2017/common_modulus)_

## Common Modulus 1
> We made RSA Encryption Scheme/Tester. Can you break it?
> [Common_Modulus_1.zip](https://github.com/khalednassar/ctf_writeups/raw/master/codebluectf2017/common_modulus/Common_Modulus_1.zip-37882dbd7dd05381bbf72a11fbbdb3f23def0e4981bc9ffcd399e4c138549fc8)

## Common Modulus 2
> The previous one is very easy. so is this also easy?
> [Common_Modulus_2.zip](https://github.com/khalednassar/ctf_writeups/raw/master/codebluectf2017/common_modulus/Common_Modulus_2.zip-24d74ea8d1b7bc154d30bb667f6f13ef24a9fe260a7741caab427421d1070c98)

## Common Modulus 3
> try harder!
> [Common_Modulus_3.zip](https://github.com/khalednassar/ctf_writeups/raw/master/codebluectf2017/common_modulus/Common_Modulus_3.zip-275005199fd0ecbec4183fd7e1b421f65c7bb982ffba65a12a4089e263899152)

The common setting is that we're given two RSA-encrypted messages \\((c_1, c_2)\\) which are the encryptions of the flag \\(m\\) such that \\(c_1\\) is the encryption of \\(m\\) with the public key \\((n, e_1)\\) and \\(c_2\\) is the encryption of \\(m\\) with the public key \\((n, e_2)\\). In other words, we have two encryptions of the same message with public keys that share the same modulus. To be precise, what we have is

1. \\(c_1 = m^{e_1} \mod n\\)
2. \\(c_2 = m^{e_2} \mod n\\)
3. \\(e_1, e_2\\) are randomly generated primes in the first challenge, which are each multiplied by 3 and 17 for the second and third challenges respectively.
4. \\(n\\) which is the common modulus to both public keys, a large randomly generated [semiprime](https://en.wikipedia.org/wiki/Semiprime) of length 2048, 4096 and 8192 bits respectively for the first, second and third challenges.

In terms of operations that we can do, we can multiply both ciphertexts to get a third ciphertext \\(c_m\\). That is because textbook RSA is [homomorphic](https://en.wikipedia.org/wiki/Homomorphism) with regards to (integer) multiplication. This operation would yield

$$
\begin{align}
& c_m & \mod n\\\\
& = c_1 \cdot c_2 & \mod n\\\\
& = m^{e_1} \cdot m^{e_2} & \mod n\\\\
& = m^{e_1 + e_2} & \mod n
\end{align}
$$

And if we were to raise \\(c_1\\) and \\(c_2\\) to the powers of \\(x\\) and \\(y\\), respectively, then multiply them together

$$
\begin{align}
c_m = c_1^{x} \cdot c_2^{y} & = (m^{e_1})^{x} \cdot (m^{e_2})^{y} & \mod n\\\\
& = m^{e_1 \cdot x} \cdot m^{e_2 \cdot y} & \mod n\\\\
& = m^{x \cdot e_1} \cdot m^{y \cdot e_2} & \mod n\\\\
& = m^{x \cdot e_1 + y \cdot e_2} & \mod n
\end{align}
$$

At this point, we can take advantage of [Bézout's identity](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity), which simply states

> For \\(a, b \in \mathbb{Z}^{+}\\) and their greatest common divisor \\(d\\), there are \\(x, y \in \mathbb{Z}\\) such that
> $$x \cdot a + y \cdot b = d$$
 
We can calculate \\(x\\) and \\(y\\) efficiently using the [Extended Euclidean Algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm). If one of the coefficients happens to be negative, then we compute the modular inverse of the respective ciphertext \\(\mod n\\) first, and raise it to the power of the absolute value of the coefficient. After calculating \\(c_m\\), we have three different cases. One for each challenge

### Common Modulus 1
This is the simplest variation, because \\(e_1\\) and \\(e_2\\) are relatively prime, meaning that their greatest common divisor is 1, so it yields

$$
\begin{align}
c_m = c_1^{x} \cdot c_2^{y} & = m^{e_1 \cdot x} \cdot m^{e_2 \cdot y} & \mod n & \\\\
& = m^{e_1 \cdot x + e_2 \cdot y} & \mod n & \\\\
& = m^{1} & \mod n & \quad \text{By Bézout's identity} \\\\
& = m
\end{align}
$$

So we've successfully recovered the first message, and hence the the first flag: `CBCTF{6ac2afd2fc108894db8ab21d1e30d3f3}`.

### Common Modulus 2
For this variation, we don't recover the message itself but instead we get \\(m^3 \mod n\\). However, we know that the flag is of the form
```
CBCTF{ ... 32 characters representing a hex-encoded MD5 hash ... }
```
Meaning that the bit length of the flag is
1. 32 characters of the hash, at 8-bits per character, 256 bits +
2. 5 characters of `CBCTF`, at 8-bits per character, 40 bits +
3. 2 charactes for `{` and `}`, at 8-bits per character, 16 bits =

312 bits, and when multiplied by 3 (because this is the 3rd power), would be in the vicinity of 936 bits. This is a lot less than the bit length of \\(n\\), which is 4096 bits for the second challenge. What this means is that we can simply take the cubic root of \\(m^3 \mod n\\), yielding \\(m\\) and hence the flag: `CBCTF{d65718235c137a94264f16d3a51fefa1}`.

### Common Modulus 3
In this variation, the hardest of the three, not only is the greatest common divisor of \\(e_1\\) and \\(e_2\\) 17, but the flag is also right-padded with null bytes (bytes with the value 0) until it's in the vicinity of ~8192 bits (a few bits less) before being encrypted. To start, we utilize the same method to get \\(m_p^{17} \mod n\\), where \\(m_p\\) is the padded flag. But we need to retrieve \\(m\\), not \\(m_p^{17}\\). How do we do that? Well, there are two things to keep in mind:

1. The modulus is quite large at 8192, meaning that the - unpadded - message must be at least 482 bits (8192 / 17 bits) so that the 17th power becomes sort of a problem. Therefore, knowing the length of the message is 312 bits because it follows the same format as the other challenges in this CTF, we can actually calculate the 17th root of \\(m^{17} \mod n\\) and successfully recover the flag IF there were no padding.
2. The padding is deterministic and linear. It is the equivalent of multiplying the flag with a very large power of 2, since the bitstring representation would be \\(XXXXX...0000000000000...0\\) where \\(XXXXX\\) is the binary representation of the coveted flag.

Using these two facts stated above, we can _unpad_ the message by first calculating the **padding coefficient**[^pad_coeff] which is \\(2^B \mod n\\) where \\(B = \\) the number of bits needed to pad the message to be close to 8192 bits, which is \\(8192 - 312 = ~7880\\) bits. Afterwards, we get the modular inverse for the previously calculated padding coefficient, yielding \\(2^{-B} \mod n\\). We then calculate \\(2^{-B \cdot 17} \mod n\\) by raising the previous value to the power of 17. Now, if we multiply that with \\(m_p^{17}\\) what we get is

$$
\begin{align}
& m_p^{17} \cdot 2^{-B \cdot 17} & \mod n\\\\
& = (m \cdot 2^{B})^{17} \cdot 2^{-B \cdot 17} & \mod n\\\\
& = (m^{17} \cdot 2^{B \cdot 17}) \cdot 2^{-B \cdot 17} & \mod n\\\\
& = m^{17} \cdot (2^{B \cdot 17} \cdot 2^{-B \cdot 17} & \mod n\\\\
& = m^{17} \cdot (2^{(B \cdot 17) + (-B \cdot 17)}) & \mod n\\\\
& = m^{17} \cdot 1 & \mod n
\end{align}
$$

So we've successfully calculated \\(m^{17} \mod n\\) and, as previously mentioned, we can also calculate the 17th root to recover \\(m\\) itself.

But wait, we haven't actually decided what \\(B\\) is! Well, in the worst case, we're going to be a few bits off from the real value, so we can simply write a program that does all the steps described above, retrieves a candidate \\(m\\) and checks that it starts with the expected `CBCTF`. We can use a conservative starting value \\(B = 7868\\), and within only 4 attempts, we recover the flag: `CBCTF{b5c96e00cb90d11ec6eccdc58ef0272d}`.

[^pad_coeff]: _Probably_ not a real term. It simply seemed apt.
