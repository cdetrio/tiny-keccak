//! An implementation of sha3, shake, keccak and KangarooTwelve functions.
//!
//! ## Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! tiny-keccak = "1.5"
//! ```
//!
//! ## Features
//! - keccak (enabled by default)
//! - k12 (**not** enabled by default, implements KangarooTwelve)
//!
//! Inspired by implementations:
//! - [keccak-tiny](https://github.com/coruus/keccak-tiny)
//! - [GoKangarooTwelve](https://github.com/mimoo/GoKangarooTwelve)
//!
//! License: CC0, attribution kindly requested. Blame taken too,
//! but not liability.

#![no_std]


extern "C" {
    fn eth2_debug();
}


const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = 25;

macro_rules! keccak_function {
    ($name: ident, $rounds: expr, $rc: expr) => {

        #[allow(unused_assignments)]
        #[allow(non_upper_case_globals)]
        pub fn $name(a: &mut [u64; $crate::WORDS]) {
            // a is the buffer
            // array is some new kind of output / context..
            use crunchy::unroll;

            for i in 0..$rounds {
                let mut array: [u64; 5] = [0; 5];
                //assert!(array.len() == 5);
                //assert!(a.len() == 25);
                // Theta
                unroll! {
                    for x in 0..5 {
                        unroll! {
                            for y_count in 0..5 {
                                //assert!(array.len() == 5);
                                //assert!(a.len() == 25);
                                let y = y_count * 5;
                                array[x] ^= a[x + y];
                            }
                        }
                    }
                }

                unroll! {
                    for x in 0..5 {
                        unroll! {
                            for y_count in 0..5 {
                                //assert!(array.len() == 5);
                                //assert!(a.len() == 25);
                                let y = y_count * 5;
                                a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                            }
                        }
                    }
                }

                // Rho and pi
                let mut last = a[1];
                unroll! {
                    for x in 0..24 {
                        //assert!(array.len() == 5);
                        //assert!(a.len() == 25);
                        array[0] = a[$crate::PI[x]];
                        a[$crate::PI[x]] = last.rotate_left($crate::RHO[x]);
                        last = array[0];
                    }
                }

                // Chi
                unroll! {
                    for y_step in 0..5 {
                        let y = y_step * 5;

                        unroll! {
                            for x in 0..5 {
                                //assert!(array.len() == 5);
                                //assert!(a.len() == 25);
                                array[x] = a[y + x];
                            }
                        }

                        unroll! {
                            for x in 0..5 {
                                //assert!(array.len() == 5);
                                //assert!(a.len() == 25);
                                a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                            }
                        }
                    }
                };

                //assert!($rc.len() >= i);
                assert!($rc.len() == 24);
                // Iota
                a[0] ^= $rc[i];
            }
        }

    }
}

#[cfg(feature = "k12")]
mod kangaroo;

#[cfg(feature = "keccak")]
mod keccak;

#[cfg(feature = "k12")]
pub use kangaroo::{k12, KangarooTwelve, keccakf as keccakf12};

#[cfg(feature = "keccak")]
pub use keccak::*;

trait Permutation {
    fn execute(a: &mut Buffer);
}

#[derive(Default, Clone)]
struct Buffer([u64; WORDS]);
// WORDS = 25, so this allocates (25*64/8) == 200 bytes


impl Buffer {
    fn words(&mut self) -> &mut [u64; WORDS] {
        &mut self.0
    }

    /*
    fn clear(&mut self) {
        for word in self.0.iter_mut() {
            word = &mut 0u64;
        }
        //Buffer::default()
    }
    */

    #[cfg(target_endian = "little")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        
        // use a wasm call(eth2_debug) to figure out where the slice check is located exactly
        //unsafe { eth2_debug(); }

        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };


        //let end = offset+len;
        //println!("execute offset: {:?}  len: {:?}", offset, len);

        //assert!(offset < WORDS * 8); // this one definitely helps
        //assert!(len < WORDS * 8); // this one definitely rteplaces a len_fail with a panic

        //assert!(end < WORDS * 8);
        //assert!(end > offset);
        /*
        (call $_ZN4core5slice20slice_index_len_fail17hb115deb2b20f49d8E
          (local.get $l2)
          (i32.const 200))
        (unreachable))
        (call $_ZN4core5slice20slice_index_len_fail17hb115deb2b20f49d8E
        (local.get $l2)
        (local.get $l5))
        (unreachable))
        (call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        (i32.const 1048576))
        (unreachable))
        (call $_ZN4core5slice20slice_index_len_fail17hb115deb2b20f49d8E
        (local.get $l4)
        (i32.const 200))
        (unreachable))
        (call $_ZN4core5slice20slice_index_len_fail17hb115deb2b20f49d8E
        (local.get $l4)
        (local.get $l5))
        */

        
        //assert!(buffer.len() > len); // same effect as above

        //assert!(WORDS * 8 - offset > len);


        // this is the check for block $B3 - that len < 200 (becauase buffer is only WORDS * 8 = 200)
        /*
        end
        i32.const 1048736
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        end
        i32.const 1048676
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        end
        i32.const 1048576
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        end
        i32.const 1048736
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        end
        i32.const 1048676
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable)
        */

        //f(&mut buffer[offset..][..len]);

        f(&mut buffer[offset..][..len]);
        //unsafe { eth2_debug(); }
        //f(&mut buffer[offset..end]);
        //f(&mut buffer[offset..len]);
    }

    /*
    #[cfg(target_endian = "big")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        fn swap_endianess(buffer: &mut [u64]) {
            for item in buffer {
                *item = item.swap_bytes();
            }
        }

        let start = offset / 8;
        let end = (offset + len + 7) / 8;
        swap_endianess(&mut self.0[start..end]);
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        swap_endianess(&mut self.0[start..end]);
    }
    */

    fn setout(&mut self, dst: &mut [u8; 32], offset: usize) {
    // the offset is always 0 and the len is always 32
    //fn setout(&mut self, dst: &mut [u8; 32], offset: usize, len: usize) {

        // assert!(dst.len() >= len); // makes no difference

        /*
        end
        i32.const 1048676
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        end
        local.get $l2
        i32.const 200
        call $_ZN4core5slice20slice_index_len_fail17hb115deb2b20f49d8E
        unreachable
        end
        i32.const 1048576
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        end
        i32.const 1048676
        call $_ZN4core9panicking5panic17h62fdcfa056e70982E
        unreachable
        */
        /*
        self.execute(offset, len, |buffer| {
            // assert!(buffer.len() == len); // makes no difference
            dst[..len].copy_from_slice(buffer);
        });
        */
        /*
        fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        }
        */


        /*
        // this works
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
        dst.copy_from_slice(&buffer[0..32]);
        */

        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
        dst.copy_from_slice(&buffer[0..32]);


        //let buffer: *mut u8 = self.0.as_mut_ptr() as *mut u8;



        /*
        let mut buffer: [u8; WORDS * 8] = unsafe { core::mem::transmute_copy(&mut self.0) };
        dst[..len].copy_from_slice(&buffer[offset..][..len]);
        */
    }


    
    fn xorinfresh(&mut self, src: &[u8], offset: usize, len: usize) {
        let buffer: *mut u8 = self.0.as_mut_ptr() as *mut u8;
        let mut src_ptr = src.as_ptr();
        unsafe {
            let mut dst_ptr = buffer.offset(offset as isize);

            for _ in 0..len {
                //*dst_ptr ^= *src_ptr;
                // fresh sponge buffer dst_ptr is all zeros. just xor by 0 so don't have to read the memory 
                *dst_ptr = 0 ^ *src_ptr;
                src_ptr = src_ptr.offset(1);
                dst_ptr = dst_ptr.offset(1);
            }
        }
    }


    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        //unsafe { eth2_debug(); }
        /*
        self.execute(offset, len, |dst| {
            //assert!(dst.len() <= src.len());
            unsafe { eth2_debug(); }
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                //assert!(dst.len() <= src.len());
                unsafe { eth2_debug(); }
                unsafe {
                    *dst_ptr ^= *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
        */


        let buffer: *mut u8 = self.0.as_mut_ptr() as *mut u8;
        //let dst_len = (200 - offset) + len;
        //let dst_len = len;
        let mut src_ptr = src.as_ptr();
        unsafe {
            let mut dst_ptr = buffer.offset(offset as isize);

            for _ in 0..len {
                //assert!(dst.len() <= src.len());
                *dst_ptr ^= *src_ptr;
                src_ptr = src_ptr.offset(1);
                dst_ptr = dst_ptr.offset(1);
            }
        }


        /*
        // this one works
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
        let dst = &mut buffer[offset..][..len];
        let len = dst.len();
        let mut dst_ptr = dst.as_mut_ptr();
        let mut src_ptr = src.as_ptr();
        for _ in 0..len {
            //assert!(dst.len() <= src.len());
            unsafe { eth2_debug(); }
            unsafe {
                *dst_ptr ^= *src_ptr;
                src_ptr = src_ptr.offset(1);
                dst_ptr = dst_ptr.offset(1);
            }
        }
        */


        /*
        let mut buffer: [u8; WORDS * 8] = unsafe { core::mem::transmute_copy(&mut self.0) };
        let dst = &mut buffer[offset..][..len];
        let len = dst.len();
        let mut dst_ptr = dst.as_mut_ptr();
        let mut src_ptr = src.as_ptr();
        for _ in 0..len {
            //assert!(dst.len() <= src.len());
            unsafe { eth2_debug(); }
            unsafe {
                *dst_ptr ^= *src_ptr;
                src_ptr = src_ptr.offset(1);
                dst_ptr = dst_ptr.offset(1);
            }
        }
        */
    }

    fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        //self.execute(offset, 1, |buff| buff[0] ^= delim);
        //self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);

        /*
        fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        */

        /*
        // this works
        let buffer1: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };

        let mut buf1 = &mut buffer1[offset..][..1];
        buf1[0] ^= delim;
        */

        //let mut buffer1: [u8; WORDS * 8] = self.0.as_mut_ptr();
        //                                   ^^^^^^^^^^^^^^^^^^^ expected array of 200 elements, found *-ptr
        // this is correct
        let buffer1: *mut u8 = self.0.as_mut_ptr() as *mut u8;
        unsafe {
            let mut buf1 = buffer1.offset(offset as isize);
            *buf1 ^= delim;
        }
        
        unsafe {
            let mut buf2 = buffer1.offset(135);
            *buf2 ^= 0x80;
        }


        /*
        let mut buffer1: [u8; WORDS * 8] = unsafe { core::mem::transmute_copy(&mut self.0) };
        //let mut buf1 = &mut buffer1[offset..][..1];
        //assert!(buffer.len() > offset+1);
        //let mut buf1 = &mut buffer1[offset..(offset+1)];

        //let mut buf1 = &mut buffer1[offset..][..1];
        //buf1[0] ^= delim;

        buffer1[offset..][..1][0] ^= delim;
        */

       /*
        unsafe {
            let mut buf1 = buffer1.get_unchecked_mut(offset);
            *buf1 ^= delim;
        }
        */

        //self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);

        /*
        let mut buffer2: [u8; WORDS * 8] = unsafe { core::mem::transmute_copy(&mut self.0) };
        //let mut buf2 = &mut buffer2[135..][..1];
        //assert!(buffer2.len() > 136);
        let mut buf2 = &mut buffer2[135..136];
        buf2[0] ^= 0x80;
        */
    }
}

struct KeccakFamily<P> {
    buffer: Buffer,
    offset: usize,
    fresh: bool,
    rate: usize,
    delim: u8,
    permutation: core::marker::PhantomData<P>,
}

impl <P> Clone for KeccakFamily<P> {
    fn clone(&self) -> Self {
        KeccakFamily {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            fresh: self.fresh,
            delim: self.delim,
            permutation: core::marker::PhantomData,
        }
    }
}

impl <P: Permutation> KeccakFamily<P> {
    fn new(rate: usize, delim: u8) -> Self {
        //println!("KeccakFamily new.");
        //assert!(rate != 0, "rate cannot be equal 0");
        KeccakFamily {
            buffer: Buffer::default(),
            offset: 0,
            fresh: true,
            rate,
            delim,
            permutation: core::marker::PhantomData,
        }
    }

    fn keccakf(&mut self) {
        P::execute(&mut self.buffer);
    }

    fn reset(&mut self) {
        // reset buffer and state to zero
        // then keccak object can take a new update
        // currently we can't reuse the keccak object
        self.offset = 0;
        //self.buffer = Buffer::default();
    }

    /*
    fn clear_buffer(&mut self) {
        self.buffer.clear();
    }
    */

    #[no_mangle]
    pub extern "C" fn update(&mut self, input: &[u8]) {
        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        // rate is 136

        // TODO: if this is the first block, then could xor bytes against i32.const 0
        // instead of xoring against memory filled with zeros

        if self.fresh {
            self.buffer.xorinfresh(&input[ip..], offset, rate);
            self.offset = offset + l;

            // if length < (self.rate - self.offset), then we need more bytes to fill up the first 136 byte block
            // don't set fresh = false yet
            if l < rate {
                return;
            }

            // if we just filled the first block, then set fresh to false and call the keccak function
            self.fresh = false;
            self.keccakf();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }


        while l >= rate {
            //assert!(input.len() > ip);
            assert!(input.len() > ip); // needed to get rid of a slice_index_order_fail
            // TODO: remove slice length check completely
            //unsafe { eth2_debug(); }
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccakf();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }


        // Xor in the last block
        assert!(ip < input.len()); // needed to get rid of a slice_index_order_fail
        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    fn squeeze(&mut self, output: &mut [u8; 32]) {
        // second foldp
        //let mut op = 0;
        //let mut l = output.len();
        // we know that the output is 32;
        //let mut l = 32;

        // rate is 136
        /*
        while l >= self.rate {
            //assert!(output.len() > op); // moves the slice index order fail, doesn't get rid of it
            //assert!(op < output.len());
            // setout (dst, offset, len)
            // setout calls execute(offset, len, buffer)
            // execute is (offset, len)
            self.buffer.setout(&mut output[op..], 0, self.rate);
            self.keccakf();
            op += self.rate;
            l -= self.rate;
        }

        //assert!(output.len() > op);
        self.buffer.setout(&mut output[op..], 0, l);
        */



        // if output length matches the rate exactly, the loop should be much simpler.
        // this works
        self.buffer.setout(output, 0);
    }

    #[no_mangle]
    pub extern "C" fn finalize(&mut self, output: &mut [u8; 32]) {
        self.pad();

        // apply keccakf
        self.keccakf();

        // squeeze output
        self.squeeze(output);
    }
}
