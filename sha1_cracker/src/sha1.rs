const BLOCK_SIZE: usize = 64;

pub struct Sha1 {
    h: [u32; 5],
    len: u64,
    block: [u8; BLOCK_SIZE],
    block_len: usize,
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            block: [0; BLOCK_SIZE],
            block_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            if self.block_len == BLOCK_SIZE {
                self.process_block();
                self.block_len = 0;
            }
            self.block[self.block_len] = data[i];
            self.block_len += 1;
            self.len += 1;
            i += 1;
        }
    }

    pub fn finalize(&mut self) -> String {
        let bit_len = self.len * 8;
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        if self.block_len > 56 {
            while self.block_len < BLOCK_SIZE {
                self.block[self.block_len] = 0;
                self.block_len += 1;
            }
            self.process_block();
            self.block_len = 0;
        }

        while self.block_len < 56 {
            self.block[self.block_len] = 0;
            self.block_len += 1;
        }

        for i in 0..8 {
            self.block[56 + i] = ((bit_len >> (56 - i * 8)) & 0xff) as u8;
        }

        self.process_block();

        let mut result = String::with_capacity(40);
        for &word in &self.h {
            result.push_str(&format!("{:08x}", word));
        }
        result
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 80];

        // Init w array
        for i in 0..16 {
            w[i] = ((self.block[i * 4] as u32) << 24)
                | ((self.block[i * 4 + 1] as u32) << 16)
                | ((self.block[i * 4 + 2] as u32) << 8)
                | (self.block[i * 4 + 3] as u32);
        }

        // Extend w array
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // upd: hash values
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}
