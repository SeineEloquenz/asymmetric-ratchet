//! Implements Hierarchical Identity-Based Encryption from Affine MACs, as described by Olivier
//! Blazy, Eike Kiltz and Jiaxin Pan.
//!
//! See <https://eprint.iacr.org/2014/581.pdf>
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt};
use derive_more::{Add, AddAssign, From, Into, Mul, MulAssign, Sub, Sum};
use ff::Field;
use group::Group;
use nalgebra::{
    matrix, vector, Dim, Matrix, Matrix1, Matrix1x2, Matrix2x1, OMatrix, RawStorage, Vector1,
    Vector2,
};
use num_traits::identities::{One, Zero};
use rand::{distributions::Distribution, Rng};
use std::{fmt::Debug, iter, ops::Mul};

const MAX_L: usize = 32;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct MatrixDistribution;

impl Distribution<Matrix2x1<Scalar>> for MatrixDistribution {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Matrix2x1<Scalar> {
        let first = Scalar::random(&mut *rng);
        let second = Scalar::random(&mut *rng);
        matrix![first; second]
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Add, Sub, Mul, Into, From, Sum, AddAssign, MulAssign,
)]
#[mul(forward)]
#[mul_assign(forward)]
pub struct Scalar(bls12_381::Scalar);

impl Scalar {
    pub fn random<R: Rng>(mut rng: R) -> Self {
        Self(Field::random(&mut rng))
    }
}

impl Zero for Scalar {
    fn zero() -> Self {
        Self(bls12_381::Scalar::zero())
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

impl One for Scalar {
    fn one() -> Self {
        Self(bls12_381::Scalar::one())
    }
}

trait Embeddable<G> {
    type Output;

    fn embed(&self) -> Self::Output;
}

impl Embeddable<G1Projective> for Scalar {
    type Output = G1Projective;

    fn embed(&self) -> Self::Output {
        G1Projective::generator() * self.0
    }
}

impl Embeddable<G2Projective> for Scalar {
    type Output = G2Projective;

    fn embed(&self) -> Self::Output {
        G2Projective::generator() * self.0
    }
}

impl<G, T: Embeddable<G>, R: Dim, C: Dim, S: RawStorage<T, R, C>> Embeddable<G>
    for Matrix<T, R, C, S>
where
    nalgebra::DefaultAllocator: nalgebra::base::allocator::Allocator<T::Output, R, C>,
    T: nalgebra::Scalar,
    T::Output: nalgebra::Scalar,
{
    type Output = OMatrix<T::Output, R, C>;

    fn embed(&self) -> Self::Output {
        self.map(|i| i.embed())
    }
}

impl<G, T: Embeddable<G>> Embeddable<G> for [T] {
    type Output = Vec<T::Output>;

    fn embed(&self) -> Self::Output {
        self.iter().map(Embeddable::embed).collect()
    }
}

fn embed_2<T: Embeddable<G2Projective> + ?Sized>(t: &T) -> T::Output {
    t.embed()
}

pub type MacSecret = (Matrix2x1<Scalar>, Vec<Vector2<Scalar>>, Scalar);
pub type MacSignature = (Vector2<G2Affine>, G2Affine);

pub fn mac_gen<R: Rng>(mut rng: R) -> MacSecret {
    let b = rng.sample(MatrixDistribution);
    let xs = (0..=MAX_L)
        .map(|_| vector![Scalar::random(&mut rng), Scalar::random(&mut rng)])
        .collect();
    let x = Scalar::random(&mut rng);
    (b, xs, x)
}

fn mac_raw<R: Rng>(mut rng: R, key: &MacSecret, message: &[Scalar]) -> (Vector2<Scalar>, Scalar) {
    let s = vector![Scalar::random(&mut rng)];
    let t = &key.0 * s;
    // sum { m_i + x_i }
    let sum = message
        .iter()
        .zip(key.1[1..].iter())
        .map(|(m, x)| x.transpose() * *m)
        .sum::<Matrix1x2<Scalar>>();
    // x_0 + sum { m_i + x_i }
    let sum = key.1[0].transpose() + sum;

    let u = (sum * t)[0] + key.2;
    (t, u)
}

pub fn mac_tag<R: Rng>(rng: R, key: &MacSecret, message: &[Scalar]) -> MacSignature {
    let (t, u) = mac_raw(rng, key, message);
    (
        Embeddable::<G2Projective>::embed(&t).map(G2Affine::from),
        Embeddable::<G2Projective>::embed(&u).into(),
    )
}

pub fn mac_ver(key: &MacSecret, tag: &MacSignature, message: &[Scalar]) -> bool {
    let t = &tag.0;
    let sum = message
        .iter()
        .zip(key.1[1..].iter())
        .map(|(m, x)| x.transpose() * *m)
        .sum::<Matrix1x2<Scalar>>();
    let sum = key.1[0].transpose() + sum;
    // Manual "unrolled" matrix multiplication as nalgebra only supports it when the types of both
    // sides coincide
    let u = t
        .iter()
        .zip(sum.iter())
        .map(|(ti, si)| ti * si.0)
        .sum::<G2Projective>();
    let u = u + Embeddable::<G2Projective>::embed(&key.2);
    tag.1 == u.into()
}

pub type HibePublicKey = (
    Matrix2x1<G1Affine>,
    Vec<Matrix2x1<G1Affine>>,
    Matrix1<G1Affine>,
);
pub type HibeSecretKey = (MacSecret, Vec<Matrix1x2<Scalar>>, Vector1<Scalar>);
pub type HibeUserSecretKey = (Vector2<G2Affine>, G2Affine, Vector1<G2Affine>);
pub type HibeUserDeriveKey = (
    Matrix2x1<G2Affine>,
    Matrix1<G2Affine>,
    Matrix1<G2Affine>,
    Vec<(
        G2Affine,
        Matrix1<G2Affine>,
        Vector1<G2Affine>,
        Matrix1<G2Affine>,
    )>,
);
pub type HibeCiphertext = (Vector2<G1Affine>, Vector2<G1Affine>);

pub fn hibe_gen<R: Rng>(mut rng: R) -> (HibePublicKey, HibeSecretKey) {
    let a = rng.sample(MatrixDistribution);
    let mac_key = mac_gen(&mut rng);

    let mut ys = Vec::new();
    let mut zs = Vec::new();

    for xi in &mac_key.1 {
        let yi = Matrix1x2::from_fn(|_, _| Scalar::random(&mut rng));
        let zi = yi.transpose();
        let mut zi = zi.insert_column(1, Scalar::one());
        zi.column_mut(1).copy_from(xi);
        let zi = zi * a;
        ys.push(yi);
        zs.push(zi);
    }

    let y0 = vector![Scalar::random(&mut rng)];
    let z0 = y0.transpose().insert_column(1, mac_key.2) * a;

    let pk = (
        Embeddable::<G1Projective>::embed(&a).map(G1Affine::from),
        zs.into_iter()
            .map(|zi| Embeddable::<G1Projective>::embed(&zi).map(G1Affine::from))
            .collect(),
        Embeddable::<G1Projective>::embed(&z0).map(G1Affine::from),
    );
    let sk = (mac_key, ys, y0);
    (pk, sk)
}

fn f(i: usize, id: &[Scalar]) -> Scalar {
    id[i]
}

pub fn hibe_usk_gen<R: Rng>(
    mut rng: R,
    sk: &HibeSecretKey,
    id: &[Scalar],
) -> (HibeUserSecretKey, HibeUserDeriveKey) {
    #![allow(non_snake_case)]
    // k = 1
    // n = 2
    // mu = 1 (rank of B)
    let (mac_t, mac_u) = mac_raw(&mut rng, &sk.0, id);
    let v = id
        .iter()
        .zip(sk.1.iter().skip(1))
        .enumerate()
        .map(|(i, (_, yi))| yi * f(i, id) * mac_t)
        .sum::<Vector1<_>>()
        + sk.1[0] * mac_t
        + sk.2;
    let S = Matrix1::from_fn(|_, _| Scalar::random(&mut rng));
    let T = sk.0 .0 * S;
    let u = id
        .iter()
        .zip(sk.0 .1.iter().skip(1))
        .enumerate()
        .map(|(i, (_, xi))| xi.transpose() * f(i, id) * T)
        .sum::<Matrix1<_>>()
        + sk.0 .1[0].transpose() * T;
    let V = id
        .iter()
        .zip(sk.1.iter().skip(1))
        .enumerate()
        .map(|(i, (_, Yi))| Yi * f(i, id) * T)
        .sum::<Matrix1<_>>()
        + sk.1[0] * T;
    let mut ds = Vec::new();
    let mut Ds = Vec::new();
    let mut es = Vec::new();
    let mut Es = Vec::new();
    for i in id.len() + 1..=MAX_L {
        ds.push((sk.0 .1[i].transpose() * mac_t)[0]);
        Ds.push(sk.0 .1[i].transpose() * T);
        es.push(sk.1[i] * mac_t);
        Es.push(sk.1[i] * T);
    }
    let ds = embed_2(ds.as_slice());
    let Ds = embed_2(Ds.as_slice());
    let es = embed_2(es.as_slice());
    let Es = embed_2(Es.as_slice());
    let usk = (
        embed_2(&mac_t).map(G2Affine::from),
        G2Affine::from(embed_2(&mac_u)),
        embed_2(&v).map(G2Affine::from),
    );
    let udk = (
        embed_2(&T).map(G2Affine::from),
        embed_2(&u).map(G2Affine::from),
        embed_2(&V).map(G2Affine::from),
        ds.into_iter()
            .zip(Ds.into_iter())
            .zip(es.into_iter())
            .zip(Es.into_iter())
            .map(|(((d, D), e), E)| {
                (
                    d.into(),
                    D.map(G2Affine::from),
                    e.map(G2Affine::from),
                    E.map(G2Affine::from),
                )
            })
            .collect(),
    );
    (usk, udk)
}

pub fn hibe_enc<R: Rng>(mut rng: R, pk: &HibePublicKey, id: &[Scalar]) -> (Gt, HibeCiphertext) {
    let r = Vector1::from_fn(|_, _| Scalar::random(&mut rng));
    let c0 = matrix![pk.0[0] * r[0].0; pk.0[1] * r[0].0];
    let summands = iter::once(pk.1[0].map(G1Projective::from))
        .chain(
            id.iter()
                .zip(pk.1.iter().skip(1))
                .enumerate()
                .map(|(i, (_, zi))| zi.map(|e| e * f(i, id).0)),
        )
        .collect::<Vec<_>>();
    let mut c1 = summands[0];
    for summand in summands[1..].iter() {
        c1 += summand;
    }
    let c1 = matrix![c1[0] * r[0].0; c1[1] * r[0].0];
    let key = pairing(&pk.2[0], &embed_2(&r[0]).into());
    (key, (c0.map(G1Affine::from), c1.map(G1Affine::from)))
}

pub fn hibe_dec(sk: &HibeUserSecretKey, c: &HibeCiphertext) -> Gt {
    let key = pairing(&c.0[0], &sk.2[0]) + pairing(&c.0[1], &sk.1)
        - pairing(&c.1[0], &sk.0[0])
        - pairing(&c.1[1], &sk.0[1]);
    key
}

pub fn hibe_usk_del<R: Rng>(
    mut rng: R,
    usk: &HibeUserSecretKey,
    udk: &HibeUserDeriveKey,
    id: &[Scalar],
    next_id: Scalar,
) -> (HibeUserSecretKey, HibeUserDeriveKey) {
    #![allow(non_snake_case)]
    // The paper says to loop from l(id'), but since we're actually cutting away the elements here,
    // it's always the nextmost one.
    let p = 0;
    let id = id.iter().chain(iter::once(&next_id)).collect::<Vec<_>>();
    let u_hat = usk.1 + udk.3[p].0 * next_id.0;
    let v_hat = matrix![G2Affine::from(usk.2[0] + udk.3[p].2[0] * next_id.0)];
    let u_1_hat = matrix![G2Affine::from(udk.1[0] + udk.3[p].1[0] * next_id.0)];
    let V_hat = matrix![G2Affine::from(udk.2[0] + udk.3[p].3[0] * next_id.0)];

    let s_prime = matrix![Scalar::random(&mut rng)];
    let S = matrix![Scalar::random(&mut rng)];
    let t_prime = matrix![
        G2Affine::from(usk.0[0] + udk.0[0] * s_prime[0].0);
        G2Affine::from(usk.0[1] + udk.0[1] * s_prime[0].0);
    ];
    let T_prime = matrix![
        G2Affine::from(udk.0[0] * S[0].0);
        G2Affine::from(udk.0[1] * S[0].0);
    ];
    let u_prime = G2Affine::from(u_hat + u_1_hat[0] * s_prime[0].0);
    let u_1_prime = matrix![G2Affine::from(u_1_hat[0] * S[0].0)];
    let v_prime = matrix![G2Affine::from(v_hat[0] + V_hat[0] * s_prime[0].0)];
    let V_prime = matrix![G2Affine::from(V_hat[0] * S[0].0)];

    let mut tail = Vec::new();

    for (di, Di, ei, Ei) in &udk.3[1..] {
        let di_prime = G2Affine::from(di + Di[0] * s_prime[0].0);
        let Di_prime = matrix![G2Affine::from(Di[0] * S[0].0)];
        let ei_prime = vector![G2Affine::from(ei[0] + Ei[0] * s_prime[0].0)];
        let Ei_prime = matrix![G2Affine::from(Ei[0] * S[0].0)];

        tail.push((di_prime, Di_prime, ei_prime, Ei_prime));
    }

    let usk_prime = (t_prime, u_prime, v_prime);
    let udk_prime = (T_prime, u_1_prime, V_prime, tail);

    (usk_prime, udk_prime)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_signature() {
        let mut rng = rand::thread_rng();
        let key = mac_gen(&mut rng);
        let message = [Scalar::random(&mut rng), Scalar::random(&mut rng)];

        let tag = mac_tag(&mut rng, &key, &message);

        assert!(mac_ver(&key, &tag, &message));
    }

    #[test]
    fn invalid_signature() {
        let mut rng = rand::thread_rng();
        let key = mac_gen(&mut rng);
        let message = [Scalar::random(&mut rng), Scalar::random(&mut rng)];

        let tag = mac_tag(&mut rng, &key, &message);

        let message = [Scalar::random(&mut rng), Scalar::random(&mut rng)];
        assert!(!mac_ver(&key, &tag, &message));
    }

    #[test]
    fn test_hibe_gen() {
        hibe_gen(rand::thread_rng());
    }

    #[test]
    fn test_hibe_secret_gen() {
        let (_, sk) = hibe_gen(rand::thread_rng());
        let (usk, udk) = hibe_usk_gen(
            rand::thread_rng(),
            &sk,
            &[Scalar::random(rand::thread_rng())],
        );
        assert_eq!(udk.3.len(), MAX_L - 1);
    }

    #[test]
    fn test_hibe_enc_dec() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = hibe_gen(&mut rng);
        let id = &[Scalar::random(rand::thread_rng())];
        let (usk, _) = hibe_usk_gen(&mut rng, &sk, id);

        let (key1, cipher) = hibe_enc(&mut rng, &pk, id);
        let key2 = hibe_dec(&usk, &cipher);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hibe_enc_dec_wrong_id() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = hibe_gen(&mut rng);
        let id = &[Scalar::random(rand::thread_rng())];
        let (usk, _) = hibe_usk_gen(&mut rng, &sk, id);

        let id = &[Scalar::random(rand::thread_rng())];
        let (key1, cipher) = hibe_enc(&mut rng, &pk, id);
        let key2 = hibe_dec(&usk, &cipher);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hibe_delegated() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = hibe_gen(&mut rng);
        let id = &[Scalar::random(&mut rng), Scalar::random(&mut rng)];

        let (usk, udk) = hibe_usk_gen(&mut rng, &sk, &id[..1]);
        let (usk, _) = hibe_usk_del(&mut rng, &usk, &udk, &id[..1], id[1]);
        let (key1, cipher) = hibe_enc(&mut rng, &pk, id);
        let key2 = hibe_dec(&usk, &cipher);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hibe_delegated_twice() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = hibe_gen(&mut rng);
        let id = &[
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];

        let (usk, udk) = hibe_usk_gen(&mut rng, &sk, &id[..1]);
        let (usk, udk) = hibe_usk_del(&mut rng, &usk, &udk, &id[..1], id[1]);
        let (usk, _) = hibe_usk_del(&mut rng, &usk, &udk, &id[..2], id[2]);
        let (key1, cipher) = hibe_enc(&mut rng, &pk, id);
        let key2 = hibe_dec(&usk, &cipher);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hibe_delegated_wrong() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = hibe_gen(&mut rng);
        let id = &[Scalar::random(&mut rng), Scalar::random(&mut rng)];

        let (usk, udk) = hibe_usk_gen(&mut rng, &sk, &id[..1]);
        let (usk, _) = hibe_usk_del(
            &mut rng,
            &usk,
            &udk,
            &id[..1],
            Scalar::random(rand::thread_rng()),
        );
        let (key1, cipher) = hibe_enc(&mut rng, &pk, id);
        let key2 = hibe_dec(&usk, &cipher);
        assert_ne!(key1, key2);
    }
}
