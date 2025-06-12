const std = @import("std");
const assert = std.debug.assert;

pub const Huffman = struct {
    // Huffman code table as defined in RFC 7541, Appendix B
    const HuffmanEntry = struct {
        symbol: union(enum) { byte: u8, eos: void },
        code: u32,
        bits: u8,
    };

    const huffmanTable = [_]HuffmanEntry{
        .{ .symbol = .{ .byte = 0 }, .code = 0x1ff8, .bits = 13 },
        .{ .symbol = .{ .byte = 1 }, .code = 0x7fffd8, .bits = 23 },
        .{ .symbol = .{ .byte = 2 }, .code = 0xfffffe2, .bits = 28 },
        .{ .symbol = .{ .byte = 3 }, .code = 0xfffffe3, .bits = 28 },
        .{ .symbol = .{ .byte = 4 }, .code = 0xfffffe4, .bits = 28 },
        .{ .symbol = .{ .byte = 5 }, .code = 0xfffffe5, .bits = 28 },
        .{ .symbol = .{ .byte = 6 }, .code = 0xfffffe6, .bits = 28 },
        .{ .symbol = .{ .byte = 7 }, .code = 0xfffffe7, .bits = 28 },
        .{ .symbol = .{ .byte = 8 }, .code = 0xfffffe8, .bits = 28 },
        .{ .symbol = .{ .byte = 9 }, .code = 0xffffea, .bits = 24 },
        .{ .symbol = .{ .byte = 10 }, .code = 0x3ffffffc, .bits = 30 },
        .{ .symbol = .{ .byte = 11 }, .code = 0xfffffe9, .bits = 28 },
        .{ .symbol = .{ .byte = 12 }, .code = 0xfffffea, .bits = 28 },
        .{ .symbol = .{ .byte = 13 }, .code = 0x3ffffffd, .bits = 30 },
        .{ .symbol = .{ .byte = 14 }, .code = 0xfffffeb, .bits = 28 },
        .{ .symbol = .{ .byte = 15 }, .code = 0xfffffec, .bits = 28 },
        .{ .symbol = .{ .byte = 16 }, .code = 0xfffffed, .bits = 28 },
        .{ .symbol = .{ .byte = 17 }, .code = 0xfffffee, .bits = 28 },
        .{ .symbol = .{ .byte = 18 }, .code = 0xfffffef, .bits = 28 },
        .{ .symbol = .{ .byte = 19 }, .code = 0xffffff0, .bits = 28 },
        .{ .symbol = .{ .byte = 20 }, .code = 0xffffff1, .bits = 28 },
        .{ .symbol = .{ .byte = 21 }, .code = 0xffffff2, .bits = 28 },
        .{ .symbol = .{ .byte = 22 }, .code = 0x3ffffffe, .bits = 30 },
        .{ .symbol = .{ .byte = 23 }, .code = 0xffffff3, .bits = 28 },
        .{ .symbol = .{ .byte = 24 }, .code = 0xffffff4, .bits = 28 },
        .{ .symbol = .{ .byte = 25 }, .code = 0xffffff5, .bits = 28 },
        .{ .symbol = .{ .byte = 26 }, .code = 0xffffff6, .bits = 28 },
        .{ .symbol = .{ .byte = 27 }, .code = 0xffffff7, .bits = 28 },
        .{ .symbol = .{ .byte = 28 }, .code = 0xffffff8, .bits = 28 },
        .{ .symbol = .{ .byte = 29 }, .code = 0xffffff9, .bits = 28 },
        .{ .symbol = .{ .byte = 30 }, .code = 0xffffffa, .bits = 28 },
        .{ .symbol = .{ .byte = 31 }, .code = 0xffffffb, .bits = 28 },
        .{ .symbol = .{ .byte = 32 }, .code = 0x14, .bits = 6 },
        .{ .symbol = .{ .byte = 33 }, .code = 0x3f8, .bits = 10 },
        .{ .symbol = .{ .byte = 34 }, .code = 0x3f9, .bits = 10 },
        .{ .symbol = .{ .byte = 35 }, .code = 0xffa, .bits = 12 },
        .{ .symbol = .{ .byte = 36 }, .code = 0x1ff9, .bits = 13 },
        .{ .symbol = .{ .byte = 37 }, .code = 0x15, .bits = 6 },
        .{ .symbol = .{ .byte = 38 }, .code = 0xf8, .bits = 8 },
        .{ .symbol = .{ .byte = 39 }, .code = 0x7fa, .bits = 11 },
        .{ .symbol = .{ .byte = 40 }, .code = 0x3fa, .bits = 10 },
        .{ .symbol = .{ .byte = 41 }, .code = 0x3fb, .bits = 10 },
        .{ .symbol = .{ .byte = 42 }, .code = 0xf9, .bits = 8 },
        .{ .symbol = .{ .byte = 43 }, .code = 0x7fb, .bits = 11 },
        .{ .symbol = .{ .byte = 44 }, .code = 0xfa, .bits = 8 },
        .{ .symbol = .{ .byte = 45 }, .code = 0x16, .bits = 6 },
        .{ .symbol = .{ .byte = 46 }, .code = 0x17, .bits = 6 },
        .{ .symbol = .{ .byte = 47 }, .code = 0x18, .bits = 6 },
        .{ .symbol = .{ .byte = 48 }, .code = 0x0, .bits = 5 },
        .{ .symbol = .{ .byte = 49 }, .code = 0x1, .bits = 5 },
        .{ .symbol = .{ .byte = 50 }, .code = 0x2, .bits = 5 },
        .{ .symbol = .{ .byte = 51 }, .code = 0x19, .bits = 6 },
        .{ .symbol = .{ .byte = 52 }, .code = 0x1a, .bits = 6 },
        .{ .symbol = .{ .byte = 53 }, .code = 0x1b, .bits = 6 },
        .{ .symbol = .{ .byte = 54 }, .code = 0x1c, .bits = 6 },
        .{ .symbol = .{ .byte = 55 }, .code = 0x1d, .bits = 6 },
        .{ .symbol = .{ .byte = 56 }, .code = 0x1e, .bits = 6 },
        .{ .symbol = .{ .byte = 57 }, .code = 0x1f, .bits = 6 },
        .{ .symbol = .{ .byte = 58 }, .code = 0x5c, .bits = 7 },
        .{ .symbol = .{ .byte = 59 }, .code = 0xfb, .bits = 8 },
        .{ .symbol = .{ .byte = 60 }, .code = 0x7ffc, .bits = 15 },
        .{ .symbol = .{ .byte = 61 }, .code = 0x20, .bits = 6 },
        .{ .symbol = .{ .byte = 62 }, .code = 0xffb, .bits = 12 },
        .{ .symbol = .{ .byte = 63 }, .code = 0x3fc, .bits = 10 },
        .{ .symbol = .{ .byte = 64 }, .code = 0x1ffa, .bits = 13 },
        .{ .symbol = .{ .byte = 65 }, .code = 0x21, .bits = 6 },
        .{ .symbol = .{ .byte = 66 }, .code = 0x5d, .bits = 7 },
        .{ .symbol = .{ .byte = 67 }, .code = 0x5e, .bits = 7 },
        .{ .symbol = .{ .byte = 68 }, .code = 0x5f, .bits = 7 },
        .{ .symbol = .{ .byte = 69 }, .code = 0x60, .bits = 7 },
        .{ .symbol = .{ .byte = 70 }, .code = 0x61, .bits = 7 },
        .{ .symbol = .{ .byte = 71 }, .code = 0x62, .bits = 7 },
        .{ .symbol = .{ .byte = 72 }, .code = 0x63, .bits = 7 },
        .{ .symbol = .{ .byte = 73 }, .code = 0x64, .bits = 7 },
        .{ .symbol = .{ .byte = 74 }, .code = 0x65, .bits = 7 },
        .{ .symbol = .{ .byte = 75 }, .code = 0x66, .bits = 7 },
        .{ .symbol = .{ .byte = 76 }, .code = 0x67, .bits = 7 },
        .{ .symbol = .{ .byte = 77 }, .code = 0x68, .bits = 7 },
        .{ .symbol = .{ .byte = 78 }, .code = 0x69, .bits = 7 },
        .{ .symbol = .{ .byte = 79 }, .code = 0x6a, .bits = 7 },
        .{ .symbol = .{ .byte = 80 }, .code = 0x6b, .bits = 7 },
        .{ .symbol = .{ .byte = 81 }, .code = 0x6c, .bits = 7 },
        .{ .symbol = .{ .byte = 82 }, .code = 0x6d, .bits = 7 },
        .{ .symbol = .{ .byte = 83 }, .code = 0x6e, .bits = 7 },
        .{ .symbol = .{ .byte = 84 }, .code = 0x6f, .bits = 7 },
        .{ .symbol = .{ .byte = 85 }, .code = 0x70, .bits = 7 },
        .{ .symbol = .{ .byte = 86 }, .code = 0x71, .bits = 7 },
        .{ .symbol = .{ .byte = 87 }, .code = 0x72, .bits = 7 },
        .{ .symbol = .{ .byte = 88 }, .code = 0xfc, .bits = 8 },
        .{ .symbol = .{ .byte = 89 }, .code = 0x73, .bits = 7 },
        .{ .symbol = .{ .byte = 90 }, .code = 0xfd, .bits = 8 },
        .{ .symbol = .{ .byte = 91 }, .code = 0x1ffb, .bits = 13 },
        .{ .symbol = .{ .byte = 92 }, .code = 0x7fff0, .bits = 19 },
        .{ .symbol = .{ .byte = 93 }, .code = 0x1ffc, .bits = 13 },
        .{ .symbol = .{ .byte = 94 }, .code = 0x3ffc, .bits = 14 },
        .{ .symbol = .{ .byte = 95 }, .code = 0x22, .bits = 6 },
        .{ .symbol = .{ .byte = 96 }, .code = 0x7ffd, .bits = 15 },
        .{ .symbol = .{ .byte = 97 }, .code = 0x3, .bits = 5 },
        .{ .symbol = .{ .byte = 98 }, .code = 0x23, .bits = 6 },
        .{ .symbol = .{ .byte = 99 }, .code = 0x4, .bits = 5 },
        .{ .symbol = .{ .byte = 100 }, .code = 0x24, .bits = 6 },
        .{ .symbol = .{ .byte = 101 }, .code = 0x5, .bits = 5 },
        .{ .symbol = .{ .byte = 102 }, .code = 0x25, .bits = 6 },
        .{ .symbol = .{ .byte = 103 }, .code = 0x26, .bits = 6 },
        .{ .symbol = .{ .byte = 104 }, .code = 0x27, .bits = 6 },
        .{ .symbol = .{ .byte = 105 }, .code = 0x6, .bits = 5 },
        .{ .symbol = .{ .byte = 106 }, .code = 0x74, .bits = 7 },
        .{ .symbol = .{ .byte = 107 }, .code = 0x75, .bits = 7 },
        .{ .symbol = .{ .byte = 108 }, .code = 0x28, .bits = 6 },
        .{ .symbol = .{ .byte = 109 }, .code = 0x29, .bits = 6 },
        .{ .symbol = .{ .byte = 110 }, .code = 0x2a, .bits = 6 },
        .{ .symbol = .{ .byte = 111 }, .code = 0x7, .bits = 5 },
        .{ .symbol = .{ .byte = 112 }, .code = 0x2b, .bits = 6 },
        .{ .symbol = .{ .byte = 113 }, .code = 0x76, .bits = 7 },
        .{ .symbol = .{ .byte = 114 }, .code = 0x2c, .bits = 6 },
        .{ .symbol = .{ .byte = 115 }, .code = 0x8, .bits = 5 },
        .{ .symbol = .{ .byte = 116 }, .code = 0x9, .bits = 5 },
        .{ .symbol = .{ .byte = 117 }, .code = 0x2d, .bits = 6 },
        .{ .symbol = .{ .byte = 118 }, .code = 0x77, .bits = 7 },
        .{ .symbol = .{ .byte = 119 }, .code = 0x78, .bits = 7 },
        .{ .symbol = .{ .byte = 120 }, .code = 0x79, .bits = 7 },
        .{ .symbol = .{ .byte = 121 }, .code = 0x7a, .bits = 7 },
        .{ .symbol = .{ .byte = 122 }, .code = 0x7b, .bits = 7 },
        .{ .symbol = .{ .byte = 123 }, .code = 0x7ffe, .bits = 15 },
        .{ .symbol = .{ .byte = 124 }, .code = 0x7fc, .bits = 11 },
        .{ .symbol = .{ .byte = 125 }, .code = 0x3ffd, .bits = 14 },
        .{ .symbol = .{ .byte = 126 }, .code = 0x1ffd, .bits = 13 },
        .{ .symbol = .{ .byte = 127 }, .code = 0xffffffc, .bits = 28 },
        .{ .symbol = .{ .byte = 128 }, .code = 0xfffe6, .bits = 20 },
        .{ .symbol = .{ .byte = 129 }, .code = 0x3fffd2, .bits = 22 },
        .{ .symbol = .{ .byte = 130 }, .code = 0xfffe7, .bits = 20 },
        .{ .symbol = .{ .byte = 131 }, .code = 0xfffe8, .bits = 20 },
        .{ .symbol = .{ .byte = 132 }, .code = 0x3fffd3, .bits = 22 },
        .{ .symbol = .{ .byte = 133 }, .code = 0x3fffd4, .bits = 22 },
        .{ .symbol = .{ .byte = 134 }, .code = 0x3fffd5, .bits = 22 },
        .{ .symbol = .{ .byte = 135 }, .code = 0x7fffd9, .bits = 23 },
        .{ .symbol = .{ .byte = 136 }, .code = 0x3fffd6, .bits = 22 },
        .{ .symbol = .{ .byte = 137 }, .code = 0x7fffda, .bits = 23 },
        .{ .symbol = .{ .byte = 138 }, .code = 0x7fffdb, .bits = 23 },
        .{ .symbol = .{ .byte = 139 }, .code = 0x7fffdc, .bits = 23 },
        .{ .symbol = .{ .byte = 140 }, .code = 0x7fffdd, .bits = 23 },
        .{ .symbol = .{ .byte = 141 }, .code = 0x7fffde, .bits = 23 },
        .{ .symbol = .{ .byte = 142 }, .code = 0xffffeb, .bits = 24 },
        .{ .symbol = .{ .byte = 143 }, .code = 0x7fffdf, .bits = 23 },
        .{ .symbol = .{ .byte = 144 }, .code = 0xffffec, .bits = 24 },
        .{ .symbol = .{ .byte = 145 }, .code = 0xffffed, .bits = 24 },
        .{ .symbol = .{ .byte = 146 }, .code = 0x3fffd7, .bits = 22 },
        .{ .symbol = .{ .byte = 147 }, .code = 0x7fffe0, .bits = 23 },
        .{ .symbol = .{ .byte = 148 }, .code = 0xffffee, .bits = 24 },
        .{ .symbol = .{ .byte = 149 }, .code = 0x7fffe1, .bits = 23 },
        .{ .symbol = .{ .byte = 150 }, .code = 0x7fffe2, .bits = 23 },
        .{ .symbol = .{ .byte = 151 }, .code = 0x7fffe3, .bits = 23 },
        .{ .symbol = .{ .byte = 152 }, .code = 0x7fffe4, .bits = 23 },
        .{ .symbol = .{ .byte = 153 }, .code = 0x1fffdc, .bits = 21 },
        .{ .symbol = .{ .byte = 154 }, .code = 0x3fffd8, .bits = 22 },
        .{ .symbol = .{ .byte = 155 }, .code = 0x7fffe5, .bits = 23 },
        .{ .symbol = .{ .byte = 156 }, .code = 0x3fffd9, .bits = 22 },
        .{ .symbol = .{ .byte = 157 }, .code = 0x7fffe6, .bits = 23 },
        .{ .symbol = .{ .byte = 158 }, .code = 0x7fffe7, .bits = 23 },
        .{ .symbol = .{ .byte = 159 }, .code = 0xffffef, .bits = 24 },
        .{ .symbol = .{ .byte = 160 }, .code = 0x3fffda, .bits = 22 },
        .{ .symbol = .{ .byte = 161 }, .code = 0x1fffdd, .bits = 21 },
        .{ .symbol = .{ .byte = 162 }, .code = 0xfffe9, .bits = 20 },
        .{ .symbol = .{ .byte = 163 }, .code = 0x3fffdb, .bits = 22 },
        .{ .symbol = .{ .byte = 164 }, .code = 0x3fffdc, .bits = 22 },
        .{ .symbol = .{ .byte = 165 }, .code = 0x7fffe8, .bits = 23 },
        .{ .symbol = .{ .byte = 166 }, .code = 0x7fffe9, .bits = 23 },
        .{ .symbol = .{ .byte = 167 }, .code = 0x1fffde, .bits = 21 },
        .{ .symbol = .{ .byte = 168 }, .code = 0x7fffea, .bits = 23 },
        .{ .symbol = .{ .byte = 169 }, .code = 0x3fffdd, .bits = 22 },
        .{ .symbol = .{ .byte = 170 }, .code = 0x3fffde, .bits = 22 },
        .{ .symbol = .{ .byte = 171 }, .code = 0xfffff0, .bits = 24 },
        .{ .symbol = .{ .byte = 172 }, .code = 0x1fffdf, .bits = 21 },
        .{ .symbol = .{ .byte = 173 }, .code = 0x3fffdf, .bits = 22 },
        .{ .symbol = .{ .byte = 174 }, .code = 0x7fffeb, .bits = 23 },
        .{ .symbol = .{ .byte = 175 }, .code = 0x7fffec, .bits = 23 },
        .{ .symbol = .{ .byte = 176 }, .code = 0x1fffe0, .bits = 21 },
        .{ .symbol = .{ .byte = 177 }, .code = 0x1fffe1, .bits = 21 },
        .{ .symbol = .{ .byte = 178 }, .code = 0x3fffe0, .bits = 22 },
        .{ .symbol = .{ .byte = 179 }, .code = 0x1fffe2, .bits = 21 },
        .{ .symbol = .{ .byte = 180 }, .code = 0x7fffed, .bits = 23 },
        .{ .symbol = .{ .byte = 181 }, .code = 0x3fffe1, .bits = 22 },
        .{ .symbol = .{ .byte = 182 }, .code = 0x7fffee, .bits = 23 },
        .{ .symbol = .{ .byte = 183 }, .code = 0x7fffef, .bits = 23 },
        .{ .symbol = .{ .byte = 184 }, .code = 0xfffea, .bits = 20 },
        .{ .symbol = .{ .byte = 185 }, .code = 0x3fffe2, .bits = 22 },
        .{ .symbol = .{ .byte = 186 }, .code = 0x3fffe3, .bits = 22 },
        .{ .symbol = .{ .byte = 187 }, .code = 0x3fffe4, .bits = 22 },
        .{ .symbol = .{ .byte = 188 }, .code = 0x7ffff0, .bits = 23 },
        .{ .symbol = .{ .byte = 189 }, .code = 0x3fffe5, .bits = 22 },
        .{ .symbol = .{ .byte = 190 }, .code = 0x3fffe6, .bits = 22 },
        .{ .symbol = .{ .byte = 191 }, .code = 0x7ffff1, .bits = 23 },
        .{ .symbol = .{ .byte = 192 }, .code = 0x3ffffe0, .bits = 26 },
        .{ .symbol = .{ .byte = 193 }, .code = 0x3ffffe1, .bits = 26 },
        .{ .symbol = .{ .byte = 194 }, .code = 0xfffeb, .bits = 20 },
        .{ .symbol = .{ .byte = 195 }, .code = 0x7fff1, .bits = 19 },
        .{ .symbol = .{ .byte = 196 }, .code = 0x3fffe7, .bits = 22 },
        .{ .symbol = .{ .byte = 197 }, .code = 0x7ffff2, .bits = 23 },
        .{ .symbol = .{ .byte = 198 }, .code = 0x3fffe8, .bits = 22 },
        .{ .symbol = .{ .byte = 199 }, .code = 0x1ffffec, .bits = 25 },
        .{ .symbol = .{ .byte = 200 }, .code = 0x3ffffe2, .bits = 26 },
        .{ .symbol = .{ .byte = 201 }, .code = 0x3ffffe3, .bits = 26 },
        .{ .symbol = .{ .byte = 202 }, .code = 0x3ffffe4, .bits = 26 },
        .{ .symbol = .{ .byte = 203 }, .code = 0x7ffffde, .bits = 27 },
        .{ .symbol = .{ .byte = 204 }, .code = 0x7ffffdf, .bits = 27 },
        .{ .symbol = .{ .byte = 205 }, .code = 0x3ffffe5, .bits = 26 },
        .{ .symbol = .{ .byte = 206 }, .code = 0xfffff1, .bits = 24 },
        .{ .symbol = .{ .byte = 207 }, .code = 0x1ffffed, .bits = 25 },
        .{ .symbol = .{ .byte = 208 }, .code = 0x7fff2, .bits = 19 },
        .{ .symbol = .{ .byte = 209 }, .code = 0x1fffe3, .bits = 21 },
        .{ .symbol = .{ .byte = 210 }, .code = 0x3ffffe6, .bits = 26 },
        .{ .symbol = .{ .byte = 211 }, .code = 0x7ffffe0, .bits = 27 },
        .{ .symbol = .{ .byte = 212 }, .code = 0x7ffffe1, .bits = 27 },
        .{ .symbol = .{ .byte = 213 }, .code = 0x3ffffe7, .bits = 26 },
        .{ .symbol = .{ .byte = 214 }, .code = 0x7ffffe2, .bits = 27 },
        .{ .symbol = .{ .byte = 215 }, .code = 0xfffff2, .bits = 24 },
        .{ .symbol = .{ .byte = 216 }, .code = 0x1fffe4, .bits = 21 },
        .{ .symbol = .{ .byte = 217 }, .code = 0x1fffe5, .bits = 21 },
        .{ .symbol = .{ .byte = 218 }, .code = 0x3ffffe8, .bits = 26 },
        .{ .symbol = .{ .byte = 219 }, .code = 0x3ffffe9, .bits = 26 },
        .{ .symbol = .{ .byte = 220 }, .code = 0xffffffd, .bits = 28 },
        .{ .symbol = .{ .byte = 221 }, .code = 0x7ffffe3, .bits = 27 },
        .{ .symbol = .{ .byte = 222 }, .code = 0x7ffffe4, .bits = 27 },
        .{ .symbol = .{ .byte = 223 }, .code = 0x7ffffe5, .bits = 27 },
        .{ .symbol = .{ .byte = 224 }, .code = 0xfffec, .bits = 20 },
        .{ .symbol = .{ .byte = 225 }, .code = 0xfffff3, .bits = 24 },
        .{ .symbol = .{ .byte = 226 }, .code = 0xfffed, .bits = 20 },
        .{ .symbol = .{ .byte = 227 }, .code = 0x1fffe6, .bits = 21 },
        .{ .symbol = .{ .byte = 228 }, .code = 0x3fffe9, .bits = 22 },
        .{ .symbol = .{ .byte = 229 }, .code = 0x1fffe7, .bits = 21 },
        .{ .symbol = .{ .byte = 230 }, .code = 0x1fffe8, .bits = 21 },
        .{ .symbol = .{ .byte = 231 }, .code = 0x7ffff3, .bits = 23 },
        .{ .symbol = .{ .byte = 232 }, .code = 0x3fffea, .bits = 22 },
        .{ .symbol = .{ .byte = 233 }, .code = 0x3fffeb, .bits = 22 },
        .{ .symbol = .{ .byte = 234 }, .code = 0x1ffffee, .bits = 25 },
        .{ .symbol = .{ .byte = 235 }, .code = 0x1ffffef, .bits = 25 },
        .{ .symbol = .{ .byte = 236 }, .code = 0xfffff4, .bits = 24 },
        .{ .symbol = .{ .byte = 237 }, .code = 0xfffff5, .bits = 24 },
        .{ .symbol = .{ .byte = 238 }, .code = 0x3ffffea, .bits = 26 },
        .{ .symbol = .{ .byte = 239 }, .code = 0x7ffff4, .bits = 23 },
        .{ .symbol = .{ .byte = 240 }, .code = 0x3ffffeb, .bits = 26 },
        .{ .symbol = .{ .byte = 241 }, .code = 0x7ffffe6, .bits = 27 },
        .{ .symbol = .{ .byte = 242 }, .code = 0x3ffffec, .bits = 26 },
        .{ .symbol = .{ .byte = 243 }, .code = 0x3ffffed, .bits = 26 },
        .{ .symbol = .{ .byte = 244 }, .code = 0x7ffffe7, .bits = 27 },
        .{ .symbol = .{ .byte = 245 }, .code = 0x7ffffe8, .bits = 27 },
        .{ .symbol = .{ .byte = 246 }, .code = 0x7ffffe9, .bits = 27 },
        .{ .symbol = .{ .byte = 247 }, .code = 0x7ffffea, .bits = 27 },
        .{ .symbol = .{ .byte = 248 }, .code = 0x7ffffeb, .bits = 27 },
        .{ .symbol = .{ .byte = 249 }, .code = 0xffffffe, .bits = 28 },
        .{ .symbol = .{ .byte = 250 }, .code = 0x7ffffec, .bits = 27 },
        .{ .symbol = .{ .byte = 251 }, .code = 0x7ffffed, .bits = 27 },
        .{ .symbol = .{ .byte = 252 }, .code = 0x7ffffee, .bits = 27 },
        .{ .symbol = .{ .byte = 253 }, .code = 0x7ffffef, .bits = 27 },
        .{ .symbol = .{ .byte = 254 }, .code = 0x7fffff0, .bits = 27 },
        .{ .symbol = .{ .byte = 255 }, .code = 0x3ffffee, .bits = 26 },
        .{ .symbol = .{ .eos = {} }, .code = 0x3fffffff, .bits = 30 }, // EOS symbol
    };

    pub fn encode(input: []const u8, allocator: *std.mem.Allocator) ![]u8 {
        var bit_buffer: u64 = 0;
        var bit_count: u6 = 0;
        var encoded = std.ArrayList(u8).init(allocator.*);
        defer encoded.deinit();

        for (input) |byte| {
            const huff = try findHuffmanEntry(byte);
            const code = huff.code;
            const code_bits: u6 = @intCast(huff.bits);

            bit_buffer = (bit_buffer << code_bits) | @as(u64, code);
            bit_count += code_bits;

            while (bit_count >= 8) {
                bit_count -= 8;
                const byte_to_append: u8 = @intCast((bit_buffer >> bit_count) & 0xFF);
                try encoded.append(byte_to_append);
                bit_buffer &= (@as(u64, 1) << bit_count) - 1; // Keep remaining bits
            }
        }

        if (bit_count > 0) {
            const bits_to_pad: u6 = 8 - bit_count;
            const bits_to_pad_u3: u3 = @intCast(bits_to_pad);
            const pad_bits = (@as(u8, 1) << bits_to_pad_u3) - 1; // bits_to_pad bits of '1's
            const buff_u8: u8 = @intCast(bit_buffer);
            const remaining_byte = ((buff_u8 << bits_to_pad_u3) | pad_bits) & 0xFF;
            try encoded.append(remaining_byte);
        }

        return encoded.toOwnedSlice();
    }

    pub fn decode(input: []const u8, allocator: *std.mem.Allocator) ![]u8 {
        var decoded = std.ArrayList(u8).init(allocator.*);
        defer decoded.deinit();

        var bit_buffer: u64 = 0;
        var bit_count: u8 = 0;

        var code: u32 = 0;
        var code_bits: u8 = 0;

        for (input) |byte| {
            bit_buffer = (bit_buffer << 8) | @as(u64, byte);
            bit_count += 8;

            while (bit_count > 0) {
                const bit_count_u6: u6 = @intCast(bit_count - 1);
                const bit_u32: u32 = @intCast((bit_buffer >> bit_count_u6) & 0x1);
                code = (code << 1) | bit_u32;
                code_bits += 1;
                bit_count -= 1;

                // Attempt to find a matching Huffman code
                var found = false;
                for (huffmanTable) |entry| {
                    if (entry.bits == code_bits and entry.code == code) {
                        if (entry.symbol == .eos) {
                            return error.InvalidHuffmanCode; // EOS within string is an error
                        }
                        try decoded.append(entry.symbol.byte);
                        code = 0;
                        code_bits = 0;
                        found = true;
                        break;
                    }
                }

                if (found) {
                    continue;
                }

                // If code length exceeds maximum code length, it's invalid
                if (code_bits > 30) {
                    return error.InvalidHuffmanCode;
                }
            }
        }

        // After processing all bits, check for remaining bits
        if (code_bits > 0) {
            // The remaining bits should be a prefix of the EOS code
            const eos_code: u32 = 0x3fffffff; // 30 bits
            const eos_bits: u5 = 30;

            const code_bits_u5: u5 = @intCast(code_bits);
            const shift: u5 = eos_bits - code_bits_u5;

            const masked_eos_code = (eos_code >> shift) & ((@as(u32, 1) << code_bits_u5) - 1);

            if (code != masked_eos_code) {
                return error.InvalidHuffmanCode; // The remaining bits don't match the EOS padding
            }
        }

        return decoded.toOwnedSlice();
    }

    fn findHuffmanEntry(byte: u8) !HuffmanEntry {
        for (huffmanTable) |entry| {
            if (entry.symbol == .byte and entry.symbol.byte == byte) return entry;
        }
        return error.InvalidInput;
    }

    fn decodeHuffmanSymbol(bits: u32) ?HuffmanEntry {
        for (huffmanTable) |entry| {
            const shift_amount: u5 = @intCast(32 - entry.bits);
            if (entry.code == (bits >> shift_amount)) {
                return entry;
            }
        }
        return null;
    }
};

test "Huffman encoding and decoding" {
    var allocator = std.testing.allocator;

    const input = "Hello, Huffman!";
    const encoded = try Huffman.encode(input, &allocator);
    defer allocator.free(encoded);

    const decoded = try Huffman.decode(encoded, &allocator);
    defer allocator.free(decoded);

    try std.testing.expect(std.mem.eql(u8, decoded, input));
}

test "Huffman encode decode consistency" {
    var allocator = std.testing.allocator;

    const inputs = [_][]const u8{
        "Hello, Huffman!",
        "Zig is great!",
        "Encode and Decode",
        "Test with different strings",
    };

    for (inputs) |input| {
        const encoded = try Huffman.encode(input, &allocator);
        defer allocator.free(encoded);

        const decoded = try Huffman.decode(encoded, &allocator);
        defer allocator.free(decoded);

        try std.testing.expect(std.mem.eql(u8, decoded, input));
    }
}

test "Huffman encoding and decoding compliance with RFC 7541" {
    var allocator = std.testing.allocator;

    const test_cases = [_][]const u8{
        "", // Empty string
        "a", // Single character
        "Hello, World!", // Simple ASCII string
        "The quick brown fox jumps over the lazy dog", // Pangram
        "0123456789", // Digits
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", // All letters
        " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", // Special characters
        "Привет мир", // Unicode characters (Cyrillic)
    };

    for (test_cases) |input| {
        // Since Huffman coding in HPACK operates on bytes, ensure the input is valid UTF-8
        const encoded = try Huffman.encode(input, &allocator);
        defer allocator.free(encoded);

        const decoded = try Huffman.decode(encoded, &allocator);
        defer allocator.free(decoded);

        try std.testing.expectEqualStrings(input, decoded);
    }
}
