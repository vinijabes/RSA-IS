use std::{
    io::Read,
    ops::{Add, Div, Mul, Rem, Sub},
};

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};

#[derive(Debug, Clone)]
pub struct PublicKey {
    e: BigUint,
    n: BigUint,
}

#[derive(Debug, Clone)]
pub struct PrivateKey {
    d: BigUint,
    n: BigUint,
}

fn is_prime(p: BigUint) -> bool {
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

const first_primes: &'static [u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349,
];

fn generate_prime_candidate(n: u8) -> BigUint {
    let zero = BigUint::from(0u64);

    loop {
        let mut p: BigUint = rand::random();
        p |= (1 << n - 1) | 1;
        p &= u64::MAX >> (64 - n);

        for d in first_primes {
            if p.clone().rem((*d).to_biguint()).eq(&zero) {}
        }

        return p;
    }
}

fn generate_prime(mut n: u8) -> BigUint {
    if n > 64 {
        n = 64;
    }

    let mut p = generate_prime_candidate(n);
    while !is_prime(p.to_biguint().unwrap()) {
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
/// let result = egcd(15, 8);
/// assert_eq!(result, (1))
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

        // x = std::mem::replace(&mut y, r);
        // a0 = std::mem::replace(&mut a1, c);
        // b0 = std::mem::replace(&mut b1, d);
        x = y;
        y = r;
        a0 = a1;
        a1 = c;
        b0 = b1;
        b1 = d;
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

pub fn generate_key() -> (PublicKey, PrivateKey) {
    let p = generate_prime(48);
    let q = generate_prime(48);

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
}

#[cfg(test)]
mod test {
    use num_bigint::{BigUint, ToBigUint};

    use crate::{generate_key, generate_prime, is_prime, PrivateKey, PublicKey};

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
        let p = generate_prime(48);
        assert_eq!(is_prime(p), true);
    }

    #[test]
    fn test_generate_key() {
        let (pub_key, priv_key) = generate_key();

        println!("{:?} {:?}", pub_key, priv_key);
    }

    #[test]
    fn test_encrypt() {
        let pub_key = PublicKey {
            n: BigUint::from(11023u64),
            e: BigUint::from(11u64),
        };

        println!("{:?}", pub_key.encrypt("How are you".as_bytes()));
    }

    #[test]
    fn test_decrypt() {
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
    fn test_decrypt_48_bits() {
        let (pub_key, private_key) = generate_key();

        let encoded = pub_key.encrypt("How are you?".as_bytes());
        assert_eq!(
            String::from_utf8(private_key.decrypt(&encoded[..])).ok(),
            Some("How are you?".to_string())
        );
    }
}
