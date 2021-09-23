use std::ops::{Add, Div, Mul, Rem, Sub};

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigUint};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct PublicKey {
    e: BigUint,
    n: BigUint,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct PrivateKey {
    d: BigUint,
    n: BigUint,
}

const FIRST_PRIMES: &'static [u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349,
];

/// Check if `p` is prime
///
/// ```
/// # use rsa::is_prime;
/// # use num_bigint::{BigUint, ToBigUint};
/// assert_eq!(is_prime(BigUint::from(7687u64)), true)
/// ```
pub fn is_prime(p: BigUint) -> bool {
    let zero = BigUint::from(0u64);
    let two = BigUint::from(2u64);
    let three = BigUint::from(3u64);
    let six = BigUint::from(6u64);

    if p <= three {
        return p > 1.to_biguint().unwrap();
    }

    if p.clone().rem(&two).eq(&zero) || p.clone().rem(&three).eq(&zero) {
        return false;
    }

    let mut i = 5.to_biguint().unwrap();

    while i.clone().pow(2) <= p.clone() {
        if p.clone().rem(&i).eq(&zero) || p.clone().rem(i.clone().add(&two)).eq(&zero) {
            return false;
        }

        i = i.add(&six);
    }
    return true;
}

/// Check if `p` is prime running `k` iterations of Rabin Miller Primality test
///
/// ```
/// # use rsa::is_probable_prime;
/// # use num_bigint::{BigUint, ToBigUint};
/// assert_eq!(is_probable_prime(&BigUint::from(7687u64), 128), true)
/// ```
pub fn is_probable_prime(p: &BigUint, k: usize) -> bool {
    let mut max_divisions_by_two = 0u32;
    let ec = p.clone() - BigUint::from(1u32);

    let mut rng = rand::thread_rng();

    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);

    let mut div_ec = ec.clone();
    while div_ec.clone() % &two == zero {
        div_ec >>= 1;
        max_divisions_by_two += 1;
    }
    assert_eq!(
        two.clone().pow(max_divisions_by_two).mul(&div_ec).eq(&ec),
        true
    );

    let p_clone = p.clone();
    let trial_composite = move |round_tester: BigUint| -> bool {
        if round_tester.modpow(&ec, &p_clone).eq(&one) {
            return false;
        }

        for i in 0..max_divisions_by_two {
            if round_tester
                .modpow(&two.clone().pow(i).mul(&ec), &p_clone)
                .eq(&ec)
            {
                return false;
            }
        }

        true
    };

    let two = BigUint::from(2u32);
    for _ in 0..k {
        let round_tester = rng.gen_biguint_range(&two, &p);
        if trial_composite(round_tester) {
            return false;
        }
    }

    true
}

fn generate_prime_candidate(n: u64) -> BigUint {
    let zero = BigUint::from(0u64);

    let mut rng = rand::thread_rng();
    'prime: loop {
        let mut p: BigUint = rng.gen_biguint(n);
        p.set_bit(n - 1, true);

        for d in FIRST_PRIMES {
            if p.clone().rem(d.to_biguint().unwrap()).eq(&zero)
                && d.to_biguint().unwrap().pow(2) <= p
            {
                continue 'prime;
            }
        }

        return p;
    }
}

/// Generate a prime number with `n` bits
/// ```
/// let prime = rsa::generate_prime(32);
/// ```
pub fn generate_prime(n: u64) -> BigUint {
    let mut p = generate_prime_candidate(n);
    // !is_prime(p.to_biguint().unwrap())
    while !is_probable_prime(&p, 128) {
        p = generate_prime_candidate(n);
    }

    p.to_biguint().unwrap()
}

/// Find the greatest common divisor and Bezout's coefficients between `a` and `b`
///
/// [`a`]: first number
/// [`b`]: second number
///
/// ```rust,ignore
/// # use rsa::egcd;
/// let result = egcd(15, 8);
/// ```
fn egcd(mut x: BigInt, mut y: BigInt) -> (BigInt, BigInt, BigInt) {
    let zero = BigInt::from(0);

    let (mut a0, mut a1, mut b0, mut b1) = (
        BigInt::from(1),
        BigInt::from(0),
        BigInt::from(0),
        BigInt::from(1),
    );

    while y != zero {
        let (q, r) = (x.clone().div(&y), x.clone().rem(&y));
        let (c, d) = (
            a0.clone().sub(q.clone().mul(&a1)),
            b0.clone().sub(&q.mul(&b1)),
        );

        // equivalent to x = y and y = r
        x = std::mem::replace(&mut y, r);

        // equivalent to a0 = a1 and a1 = c
        a0 = std::mem::replace(&mut a1, c);

        // equivalent to b0 = b1 and b1 = d
        b0 = std::mem::replace(&mut b1, d);
    }

    (x, a0, b0)
}

fn find_coprime(phi: &BigInt) -> Option<(BigInt, BigInt, BigInt)> {
    let mut e = BigInt::from(65537);

    let one = BigInt::from(1);
    while &e <= phi {
        let result = egcd(e.clone(), phi.clone());

        if result.0 == one {
            return Some((e, result.1, result.2));
        }

        e += 1;
    }

    None
}

/// Generate Public and Private RSA Key with `key_size` bits.
/// ```
/// # use rsa::generate_key;
/// let (public_key, private_key) = generate_key(2048u64);
/// ```
pub fn generate_key(key_size: u64) -> (PublicKey, PrivateKey) {
    let p = generate_prime(key_size);
    let q = generate_prime(key_size);

    let n = p.clone() * &q;

    let phi: BigInt = ((p - 1.to_biguint().unwrap()) * (q - 1.to_biguint().unwrap())).into();
    let (e, a, _) = find_coprime(&phi).unwrap();

    let d = (a % phi.clone() + phi.clone()) % phi;

    let public_key = PublicKey {
        n: n.clone(),
        e: e.to_biguint().unwrap(),
    };
    let private_key = PrivateKey {
        n,
        d: d.to_biguint().unwrap(),
    };

    (public_key, private_key)
}

impl PublicKey {
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let k: usize = (self.n.bits() / 8) as usize + if self.n.bits() % 8 > 0 { 1 } else { 0 };
        let mut result = Vec::with_capacity(data.len());

        let mut index: usize = 0;

        while index != data.len() {
            let mut next = std::cmp::min(index + k, data.len());

            let mut val = BigUint::from_bytes_be(&data[index..next]);

            if val > self.n {
                next -= 1;
                val = BigUint::from_bytes_be(&data[index..next]);
            }

            let res = val.modpow(&self.e, &self.n);
            let mut bytes = res.to_bytes_be();

            if bytes.len() < k {
                result.append(&mut vec![0u8; k - bytes.len()])
            }
            result.append(&mut bytes);

            index = next;
        }

        result
    }

    pub fn size(&self) -> u64 {
        self.n.bits()
    }
}

impl PrivateKey {
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let k: usize = (self.n.bits() / 8) as usize + if self.n.bits() % 8 > 0 { 1 } else { 0 };

        let mut result = Vec::with_capacity(data.len());

        let mut index: usize = 0;

        while index != data.len() {
            let next = std::cmp::min(index + k, data.len());

            let val = BigUint::from_bytes_be(&data[index..next]);
            let res = val.modpow(&self.d, &self.n);

            result.append(&mut res.to_bytes_be());

            index = next;
        }

        result
    }

    pub fn size(&self) -> u64 {
        self.n.bits()
    }
}

#[cfg(test)]
mod test {
    use num_bigint::{BigUint, ToBigUint};

    use crate::{generate_key, generate_prime, is_prime, is_probable_prime, PrivateKey, PublicKey};

    #[test]
    fn test_if_2_is_prime() {
        assert_eq!(is_prime(BigUint::from(2u64)), true)
    }

    #[test]
    fn test_if_3_is_prime() {
        assert_eq!(is_prime(BigUint::from(3u64)), true)
    }

    #[test]
    fn test_if_7687_is_prime() {
        assert_eq!(is_prime(BigUint::from(7687u64)), true)
    }

    #[test]
    fn test_if_7689_is_not_prime() {
        assert_eq!(is_prime(7689.to_biguint().unwrap()), false)
    }

    #[test]
    fn test_generate_prime() {
        let p = generate_prime(256);
        assert_eq!(is_probable_prime(&p, 128), true);
    }

    #[test]
    fn test_generate_key() {
        let (pub_key, priv_key) = generate_key(256);
        assert_eq!(pub_key.n, priv_key.n);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let pub_key = PublicKey {
            n: BigUint::from(11023u64),
            e: BigUint::from(11u64),
        };

        let private_key = PrivateKey {
            n: BigUint::from(11023u64),
            d: BigUint::from(5891u64),
        };

        let encoded = pub_key.encrypt("How are you?".as_bytes());
        assert_eq!(
            String::from_utf8(private_key.decrypt(&encoded[..])).ok(),
            Some("How are you?".to_string())
        );
    }

    #[test]
    fn test_encrypt_and_decrypt_256_bits() {
        let (pub_key, private_key) = generate_key(256);

        let encoded = pub_key.encrypt("How are you?".as_bytes());
        assert_eq!(
            String::from_utf8(private_key.decrypt(&encoded[..])).ok(),
            Some("How are you?".to_string())
        );
    }
}
