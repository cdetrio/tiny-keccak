use super::{KeccakFamily, Permutation, Buffer};


extern "C" {
    fn eth2_debug();
}

const ROUNDS: usize = 24;

static RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

/// keccak-f[1600, 24]
//keccak_function!(keccakf2, ROUNDS, RC);

#[inline(always)]
fn rol(x: u64, s: u32) -> u64 {
    //unsafe { eth2_debug(); }
    return (x << s) | (x >> (64 - s));
}


pub fn keccakf(state: &mut [u64; crate::WORDS]) {
    //int round;

    //let mut Aba: u64;

    let (mut Aba, mut Abe, mut Abi, mut Abo, mut Abu): (u64, u64, u64, u64, u64);
    let (mut Aga, mut Age, mut Agi, mut Ago, mut Agu): (u64, u64, u64, u64, u64);
    let (mut Aka, mut Ake, mut Aki, mut Ako, mut Aku): (u64, u64, u64, u64, u64);
    let (mut Ama, mut Ame, mut Ami, mut Amo, mut Amu): (u64, u64, u64, u64, u64);
    let (mut Asa, mut Ase, mut Asi, mut Aso, mut Asu): (u64, u64, u64, u64, u64);
    /*
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    */
    
    
    let (mut Eba, mut Ebe, mut Ebi, mut Ebo, mut Ebu): (u64, u64, u64, u64, u64);
    let (mut Ega, mut Ege, mut Egi, mut Ego, mut Egu): (u64, u64, u64, u64, u64);
    let (mut Eka, mut Eke, mut Eki, mut Eko, mut Eku): (u64, u64, u64, u64, u64);
    let (mut Ema, mut Eme, mut Emi, mut Emo, mut Emu): (u64, u64, u64, u64, u64);
    let (mut Esa, mut Ese, mut Esi, mut Eso, mut Esu): (u64, u64, u64, u64, u64);
    /*
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;
    */

    //uint64_t Ba, Be, Bi, Bo, Bu;
    let (mut Ba, mut Be, mut Bi, mut Bo, mut Bu): (u64, u64, u64, u64, u64);

    //uint64_t Da, De, Di, Do, Du;
    let (mut Da, mut De, mut Di, mut Do, mut Du): (u64, u64, u64, u64, u64);

    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    //for (let round = 0; round < 24; round += 2)
    //for round in (0..24).step_by(2) {
    let mut round = 0;
    while round < 25 {
        /* Round (round + 0): Axx -> Exx */

        Ba = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        Be = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        Bi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        Bo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        Bu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;


        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        /*
        Da = Bu ^ Be.rotate_left(1);
        De = Ba ^ Bi.rotate_left(1);
        Di = Be ^ Bo.rotate_left(1);
        Do = Bi ^ Bu.rotate_left(1);
        Du = Bo ^ Ba.rotate_left(1);
        */

        Ba = Aba ^ Da;

        Be = rol(Age ^ De, 44);
        Bi = rol(Aki ^ Di, 43);
        Bo = rol(Amo ^ Do, 21);
        Bu = rol(Asu ^ Du, 14);

        /*
        Be = (Age ^ De).rotate_left(44);
        Bi = (Aki ^ Di).rotate_left(43);
        Bo = (Amo ^ Do).rotate_left(21);
        Bu = (Asu ^ Du).rotate_left(14);
        */

        Eba = Ba ^ (!Be & Bi) ^ RC[round];
        Ebe = Be ^ (!Bi & Bo);
        Ebi = Bi ^ (!Bo & Bu);
        Ebo = Bo ^ (!Bu & Ba);
        Ebu = Bu ^ (!Ba & Be);

        Ba = rol(Abo ^ Do, 28);
        Be = rol(Agu ^ Du, 20);
        Bi = rol(Aka ^ Da, 3);
        Bo = rol(Ame ^ De, 45);
        Bu = rol(Asi ^ Di, 61);

        /*
        Ba = (Abo ^ Do).rotate_left(28);
        Be = (Agu ^ Du).rotate_left(20);
        Bi = (Aka ^ Da).rotate_left(3);
        Bo = (Ame ^ De).rotate_left(45);
        Bu = (Asi ^ Di).rotate_left(61);
        */
        Ega = Ba ^ (!Be & Bi);
        Ege = Be ^ (!Bi & Bo);
        Egi = Bi ^ (!Bo & Bu);
        Ego = Bo ^ (!Bu & Ba);
        Egu = Bu ^ (!Ba & Be);

        Ba = rol(Abe ^ De, 1);
        Be = rol(Agi ^ Di, 6);
        Bi = rol(Ako ^ Do, 25);
        Bo = rol(Amu ^ Du, 8);
        Bu = rol(Asa ^ Da, 18);

        /*
        Ba = (Abe ^ De).rotate_left(1);
        Be = (Agi ^ Di).rotate_left(6);
        Bi = (Ako ^ Do).rotate_left(25);
        Bo = (Amu ^ Du).rotate_left(8);
        Bu = (Asa ^ Da).rotate_left(18);
        */
        
        Eka = Ba ^ (!Be & Bi);
        Eke = Be ^ (!Bi & Bo);
        Eki = Bi ^ (!Bo & Bu);
        Eko = Bo ^ (!Bu & Ba);
        Eku = Bu ^ (!Ba & Be);

        Ba = rol(Abu ^ Du, 27);
        Be = rol(Aga ^ Da, 36);
        Bi = rol(Ake ^ De, 10);
        Bo = rol(Ami ^ Di, 15);
        Bu = rol(Aso ^ Do, 56);

        /*
        Ba = (Abu ^ Du).rotate_left(27);
        Be = (Aga ^ Da).rotate_left(36);
        Bi = (Ake ^ De).rotate_left(10);
        Bo = (Ami ^ Di).rotate_left(15);
        Bu = (Aso ^ Do).rotate_left(56);
        */

        Ema = Ba ^ (!Be & Bi);
        Eme = Be ^ (!Bi & Bo);
        Emi = Bi ^ (!Bo & Bu);
        Emo = Bo ^ (!Bu & Ba);
        Emu = Bu ^ (!Ba & Be);

        Ba = rol(Abi ^ Di, 62);
        Be = rol(Ago ^ Do, 55);
        Bi = rol(Aku ^ Du, 39);
        Bo = rol(Ama ^ Da, 41);
        Bu = rol(Ase ^ De, 2);

        /*
        Ba = (Abi ^ Di).rotate_left(62);
        Be = (Ago ^ Do).rotate_left(55);
        Bi = (Aku ^ Du).rotate_left(39);
        Bo = (Ama ^ Da).rotate_left(41);
        Bu = (Ase ^ De).rotate_left(2);
        */

        Esa = Ba ^ (!Be & Bi);
        Ese = Be ^ (!Bi & Bo);
        Esi = Bi ^ (!Bo & Bu);
        Eso = Bo ^ (!Bu & Ba);
        Esu = Bu ^ (!Ba & Be);


        /* Round (round + 1): Exx -> Axx */

        Ba = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        Be = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        Bi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        Bo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        Bu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        /*
        Da = Bu ^ (Be).rotate_left(1);
        De = Ba ^ (Bi).rotate_left(1);
        Di = Be ^ (Bo).rotate_left(1);
        Do = Bi ^ (Bu).rotate_left(1);
        Du = Bo ^ (Ba).rotate_left(1);
        */

        Ba = Eba ^ Da;

        Be = rol(Ege ^ De, 44);
        Bi = rol(Eki ^ Di, 43);
        Bo = rol(Emo ^ Do, 21);
        Bu = rol(Esu ^ Du, 14);

        /*
        Be = (Ege ^ De).rotate_left(44);
        Bi = (Eki ^ Di).rotate_left(43);
        Bo = (Emo ^ Do).rotate_left(21);
        Bu = (Esu ^ Du).rotate_left(14);
        */

        Aba = Ba ^ (!Be & Bi) ^ RC[round + 1];
        Abe = Be ^ (!Bi & Bo);
        Abi = Bi ^ (!Bo & Bu);
        Abo = Bo ^ (!Bu & Ba);
        Abu = Bu ^ (!Ba & Be);

        Ba = rol(Ebo ^ Do, 28);
        Be = rol(Egu ^ Du, 20);
        Bi = rol(Eka ^ Da, 3);
        Bo = rol(Eme ^ De, 45);
        Bu = rol(Esi ^ Di, 61);

        /*
        Ba = (Ebo ^ Do).rotate_left(28);
        Be = (Egu ^ Du).rotate_left(20);
        Bi = (Eka ^ Da).rotate_left(3);
        Bo = (Eme ^ De).rotate_left(45);
        Bu = (Esi ^ Di).rotate_left(61);
        */

        Aga = Ba ^ (!Be & Bi);
        Age = Be ^ (!Bi & Bo);
        Agi = Bi ^ (!Bo & Bu);
        Ago = Bo ^ (!Bu & Ba);
        Agu = Bu ^ (!Ba & Be);


        Ba = rol(Ebe ^ De, 1);
        Be = rol(Egi ^ Di, 6);
        Bi = rol(Eko ^ Do, 25);
        Bo = rol(Emu ^ Du, 8);
        Bu = rol(Esa ^ Da, 18);

        /*
        Ba = (Ebe ^ De).rotate_left(1);
        Be = (Egi ^ Di).rotate_left(6);
        Bi = (Eko ^ Do).rotate_left(25);
        Bo = (Emu ^ Du).rotate_left(8);
        Bu = (Esa ^ Da).rotate_left(18);
        */
        
        Aka = Ba ^ (!Be & Bi);
        Ake = Be ^ (!Bi & Bo);
        Aki = Bi ^ (!Bo & Bu);
        Ako = Bo ^ (!Bu & Ba);
        Aku = Bu ^ (!Ba & Be);


        Ba = rol(Ebu ^ Du, 27);
        Be = rol(Ega ^ Da, 36);
        Bi = rol(Eke ^ De, 10);
        Bo = rol(Emi ^ Di, 15);
        Bu = rol(Eso ^ Do, 56);

        /*
        Ba = (Ebu ^ Du).rotate_left(27);
        Be = (Ega ^ Da).rotate_left(36);
        Bi = (Eke ^ De).rotate_left(10);
        Bo = (Emi ^ Di).rotate_left(15);
        Bu = (Eso ^ Do).rotate_left(56);
        */

        Ama = Ba ^ (!Be & Bi);
        Ame = Be ^ (!Bi & Bo);
        Ami = Bi ^ (!Bo & Bu);
        Amo = Bo ^ (!Bu & Ba);
        Amu = Bu ^ (!Ba & Be);


        Ba = rol(Ebi ^ Di, 62);
        Be = rol(Ego ^ Do, 55);
        Bi = rol(Eku ^ Du, 39);
        Bo = rol(Ema ^ Da, 41);
        Bu = rol(Ese ^ De, 2);

        /*
        Ba = (Ebi ^ Di).rotate_left(62);
        Be = (Ego ^ Do).rotate_left(55);
        Bi = (Eku ^ Du).rotate_left(39);
        Bo = (Ema ^ Da).rotate_left(41);
        Bu = (Ese ^ De).rotate_left(2);
        */

        Asa = Ba ^ (!Be & Bi);
        Ase = Be ^ (!Bi & Bo);
        Asi = Bi ^ (!Bo & Bu);
        Aso = Bo ^ (!Bu & Ba);
        Asu = Bu ^ (!Ba & Be);

        round = round + 2;
    }

    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}



macro_rules! impl_constructor {
    ($name: ident, $alias: ident, $bits: expr, $delim: expr) => {
        pub fn $name() -> Keccak {
            Keccak::new(200 - $bits / 4, $delim)
        }

        // this is the function we currently call:  tiny_keccak::Keccak::keccak256(&block_data[..], output);
        pub fn $alias(data: &[u8], result: &mut [u8; 32]) {
            let mut keccak = Keccak::$name();
            keccak.update(data);
            keccak.finalize(result);
        }
    };
}

macro_rules! impl_global_alias {
    ($alias: ident, $size: expr) => {
        pub fn $alias(data: &[u8]) -> [u8; $size / 8] {
            let mut result = [0u8; $size / 8];
            Keccak::$alias(data, &mut result);
            result
        }
    };
}

/*
impl_global_alias!(shake128, 128);
impl_global_alias!(shake256, 256);
impl_global_alias!(keccak224, 224);
*/
impl_global_alias!(keccak256, 256);
/*
impl_global_alias!(keccak384, 384);
impl_global_alias!(keccak512, 512);
impl_global_alias!(sha3_224, 224);
impl_global_alias!(sha3_256, 256);
impl_global_alias!(sha3_384, 384);
impl_global_alias!(sha3_512, 512);
*/

struct Normal;

impl Permutation for Normal {
    #[inline]
    fn execute(buffer: &mut Buffer) {
        keccakf(buffer.words());
    }
}

/// shake, keccak and sha3 implementation.
///
/// ```rust
/// use tiny_keccak::Keccak;
///
/// fn main() {
///     let mut sha3 = Keccak::new_sha3_256();
///
///     sha3.update("hello".as_ref());
///     sha3.update(&[b' ']);
///     sha3.update("world".as_ref());
///
///     let mut res: [u8; 32] = [0; 32];
///     sha3.finalize(&mut res);
///
///     let expected = vec![
///         0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04,
///         0x09, 0x99, 0xaa, 0xc8, 0x9e, 0x76, 0x22, 0xf3,
///         0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72, 0xfd, 0x94,
///         0xa3, 0x1c, 0x3b, 0xfb, 0xf2, 0x4e, 0x39, 0x38
///     ];
///
///     let ref_ex: &[u8] = &expected;
///     assert_eq!(&res, ref_ex);
/// }
/// ```
#[derive(Clone)]
pub struct Keccak {
    state: KeccakFamily<Normal>
}

impl Keccak {
    pub fn new(rate: usize, delim: u8) -> Keccak {
        Keccak {
            state: KeccakFamily::new(rate, delim),
        }
    }

    /*
    impl_constructor!(new_shake128, shake128, 128, 0x1f);
    impl_constructor!(new_shake256, shake256, 256, 0x1f);
    impl_constructor!(new_keccak224, keccak224, 224, 0x01);
    */
    impl_constructor!(new_keccak256, keccak256, 256, 0x01);
    /*
    impl_constructor!(new_keccak384, keccak384, 384, 0x01);
    impl_constructor!(new_keccak512, keccak512, 512, 0x01);
    impl_constructor!(new_sha3_224, sha3_224, 224, 0x06);
    impl_constructor!(new_sha3_256, sha3_256, 256, 0x06);
    impl_constructor!(new_sha3_384, sha3_384, 384, 0x06);
    impl_constructor!(new_sha3_512, sha3_512, 512, 0x06);
    */

    pub fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    pub fn reset(&mut self) {
        //self.state.reset_offset();
        //self.state.clear_buffer();
        self.state.reset();
    }

    #[deprecated(
        since = "1.5.0",
        note = "Please use the update function instead"
    )]
    pub fn absorb(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    pub fn keccakf(&mut self) {
        self.state.keccakf()
    }

    pub fn finalize(&mut self, output: &mut [u8; 32]) {
        self.state.finalize(output);
    }

    pub fn pad(&mut self) {
        self.state.pad();
    }

    pub fn fill_block(&mut self) {
        self.state.keccakf();
        self.state.offset = 0;
    }

    pub fn squeeze(&mut self, output: &mut [u8; 32]) {
        self.state.squeeze(output);
    }

    /*
    #[inline]
    pub fn xof(mut self) -> XofReader {
        self.pad();

        self.keccakf();

        XofReader {
            keccak: self.state,
            offset: 0,
        }
    }
    */
}

/*
pub struct XofReader {
    keccak: KeccakFamily<Normal>,
    offset: usize,
}

impl XofReader {
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.keccak.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.keccak.buffer.setout(&mut output[op..], offset, rate);
            self.keccak.keccakf();
            op += rate;
            l -= rate;
            rate = self.keccak.rate;
            offset = 0;
        }

        self.keccak.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }
}
*/

