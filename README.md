# slowkey-js

Reference implementation of the [SlowKey](https://github.com/lbeder/slowkey) Tool in Rust.

## SlowKey: Advanced Key Derivation Tool Using Scrypt, Argon2id, SHA2, and SHA3

SlowKey is a cutting-edge [Key Derivation Function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF) tool designed to enhance cryptographic security in various applications, from securing sensitive data to protecting user passwords. At its core, SlowKey leverages the power of three renowned cryptographic algorithms: [Scrypt](https://en.wikipedia.org/wiki/Scrypt), [Argon2](https://en.wikipedia.org/wiki/Argon2), [SHA2](https://en.wikipedia.org/wiki/SHA-2), and [SHA3](https://en.wikipedia.org/wiki/SHA-3), each selected for its unique strengths in ensuring data integrity and security.

SlowKey incorporates Scrypt, a memory-hard KDF that is specifically engineered to make brute-force attacks prohibitively expensive. By requiring significant amounts of memory and processing power to compute the hash functions, Scrypt ensures that the cost and time to perform large-scale custom hardware attacks are beyond the reach of most attackers, offering robust protection against rainbow table and brute-force attacks.

SlowKey integrates Argon2, an advanced, memory-hard Key Derivation Function (KDF) designed to effectively thwart brute-force and side-channel attacks. As the winner of the Password Hashing Competition, Argon2 is tailored to ensure that the computation of hash functions demands substantial memory and processing resources, making it exceedingly difficult for attackers to mount large-scale custom hardware attacks. This requirement for significant computational effort not only increases the security against brute-force and rainbow table attacks but also provides a customizable framework that can be tuned for specific defense needs, ensuring an adaptable and formidable barrier against unauthorized access attempts.

Alongside Scrypt, and Argon2, SlowKey utilizes SHA2 and SHA3 for their exceptional hash functions, providing an additional layer of security. SHA2, a member of the Secure Hash Algorithm family, offers a high level of resistance against hash collision attacks, making it an excellent choice for secure hashing needs. SHA3, the latest member of the Secure Hash Algorithm family, further strengthens SlowKey's cryptographic capabilities with its resistance to various attack vectors, including those that may affect earlier SHA versions.

A cornerstone of SlowKey's design philosophy is its commitment to resilience through diversity. By integrating Scrypt, SHA2, and SHA3 within its cryptographic framework, SlowKey not only capitalizes on the unique strengths of each algorithm but also ensures a level of security redundancy that is critical in the face of evolving cyber threats. This strategic mixture means that even if one of these algorithms were to be compromised or "broken" due to unforeseen vulnerabilities, the overall security scheme of SlowKey would remain robust and intact, safeguarded by the uncompromised integrity of the remaining algorithms. This approach mirrors the principle of layered security in cybersecurity, where multiple defensive strategies are employed to protect against a single point of failure. Consequently, SlowKey offers an advanced, forward-thinking solution that anticipates and mitigates the potential impact of future cryptographic breakthroughs or advancements in quantum computing that could threaten individual hash functions. Through this multi-algorithm strategy, SlowKey provides a safeguard against the entire spectrum of cryptographic attacks, ensuring long-term security for its users in a landscape where the only constant is change.

## Usage

### General

```sh
slowkey-js <command>

Commands:
  slowkey-js derive  Derive a key using using Scrypt, Argon2, SHA2, and SHA3

Options:
  --help     Show help                                                                                         [boolean]
  --version  Show version number                                                                               [boolean]
```

### Deriving

```sh
slowkey-js derive

Derive a key using using Scrypt, Argon2, SHA2, and SHA3

Options:
      --help           Show help                                                                               [boolean]
      --version        Show version number                                                                     [boolean]
  -i, --iterations     Number of iterations                                                      [number] [default: 100]
  -l, --length         Length of the derived result                                               [number] [default: 16]
      --scrypt-log-n   Scrypt CPU/memory cost parameter                                           [number] [default: 20]
      --scrypt-r       Scrypt block size parameter, which fine-tunes sequential memory read size and performance
                                                                                                   [number] [default: 8]
      --scrypt-p       Scrypt parallelization parameter                                            [number] [default: 1]
      --argon2-m-cost  Argon2 number of 1 KiB memory block                                   [number] [default: 2097152]
      --argon2-t-cost  Argon2 number of iterations                                                 [number] [default: 2]
      --argon2-p-cost  Argon2 number of threads                                                    [number] [default: 4]
      --salt           Random data fed as an additional input to the KDF                             [string] [required]
      --secret         Input secret to the KFD                                                       [string] [required]
```

### Printing Test Vectors

```sh
Print test vectors

Usage: slowkey test

Options:
  -h, --help  Print help
```
