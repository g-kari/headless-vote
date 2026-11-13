/**
 * Minimal QR encoder (byte mode, error-correction level M, versions 1-10)
 * used for the poll share QR codes. No external dependency: the codeword
 * construction, Reed-Solomon over GF(256), interleaving, mask evaluation
 * and format/version information are all computed here. The matrices were
 * verified against the reference `qrcode` implementation during
 * development (see test/features-b2.test.ts for pinned spot checks).
 */

// [ecCodewordsPerBlock, [[blocks, dataCodewordsPerBlock], ...]] for level M.
const EC_TABLE: [number, [number, number][]][] = [
  [10, [[1, 16]]],
  [16, [[1, 28]]],
  [26, [[1, 44]]],
  [18, [[2, 32]]],
  [24, [[2, 43]]],
  [16, [[4, 27]]],
  [18, [[4, 31]]],
  [22, [
    [2, 38],
    [2, 39],
  ]],
  [22, [
    [3, 36],
    [2, 37],
  ]],
  [26, [
    [4, 43],
    [1, 44],
  ]],
];

const ALIGN_POSITIONS: number[][] = [
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
];

// GF(256) with primitive polynomial 0x11d.
const GF_EXP = new Array<number>(512);
const GF_LOG = new Array<number>(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255] as number;
}

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[(GF_LOG[a] as number) + (GF_LOG[b] as number)] as number;
}

function rsGenerator(degree: number): number[] {
  // Built in ascending coefficient order (constant term first); the
  // remainder routine wants the coefficients below the leading 1 in
  // descending order.
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] = (next[j] as number) ^ gfMul(poly[j] as number, GF_EXP[i] as number);
      next[j + 1] = (next[j + 1] as number) ^ (poly[j] as number);
    }
    poly = next;
  }
  return poly.slice(0, degree).reverse();
}

function rsRemainder(data: number[], generator: number[]): number[] {
  const result = new Array<number>(generator.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ (result.shift() as number);
    result.push(0);
    for (let i = 0; i < generator.length; i++) {
      result[i] = (result[i] as number) ^ gfMul(generator[i] as number, factor);
    }
  }
  return result;
}

function dataCodewords(bytes: number[], version: number): number[] {
  const [, groups] = EC_TABLE[version - 1] as [number, [number, number][]];
  const totalData = groups.reduce((sum, [count, per]) => sum + count * per, 0);
  const bits: number[] = [];
  const push = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4); // byte mode
  push(bytes.length, version >= 10 ? 16 : 8);
  for (const byte of bytes) push(byte, 8);
  const capacity = totalData * 8;
  push(0, Math.min(4, capacity - bits.length)); // terminator
  while (bits.length % 8 !== 0) bits.push(0);
  const codewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0;
    for (let j = 0; j < 8; j++) value = (value << 1) | (bits[i + j] as number);
    codewords.push(value);
  }
  const pads = [0xec, 0x11];
  for (let i = 0; codewords.length < totalData; i++) codewords.push(pads[i % 2] as number);
  return codewords;
}

function interleaveCodewords(data: number[], version: number): number[] {
  const [ecPerBlock, groups] = EC_TABLE[version - 1] as [number, [number, number][]];
  const generator = rsGenerator(ecPerBlock);
  const dataBlocks: number[][] = [];
  const ecBlocks: number[][] = [];
  let offset = 0;
  for (const [count, per] of groups) {
    for (let i = 0; i < count; i++) {
      const block = data.slice(offset, offset + per);
      offset += per;
      dataBlocks.push(block);
      ecBlocks.push(rsRemainder(block, generator));
    }
  }
  const result: number[] = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i++) {
    for (const block of dataBlocks) if (i < block.length) result.push(block[i] as number);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const block of ecBlocks) if (i < block.length) result.push(block[i] as number);
  }
  return result;
}

function formatBits(mask: number): number {
  const data = mask; // EC level M has indicator bits 00.
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

function versionBits(version: number): number {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
  return (version << 12) | rem;
}

const MASKS: ((r: number, c: number) => boolean)[] = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

export interface QrMatrix {
  size: number;
  modules: boolean[][];
}

function buildMatrix(codewords: number[], version: number, mask: number): boolean[][] {
  const size = 17 + version * 4;
  const modules: (boolean | null)[][] = Array.from({ length: size }, () =>
    new Array<boolean | null>(size).fill(null),
  );
  const set = (r: number, c: number, dark: boolean) => {
    if (r >= 0 && r < size && c >= 0 && c < size) (modules[r] as (boolean | null)[])[c] = dark;
  };
  const finder = (top: number, left: number) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const dark =
          (dr >= 0 && dr <= 6 && (dc === 0 || dc === 6)) ||
          (dc >= 0 && dc <= 6 && (dr === 0 || dr === 6)) ||
          (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
        set(top + dr, left + dc, dark);
      }
    }
  };
  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);
  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  // Alignment patterns.
  const positions = ALIGN_POSITIONS[version - 1] as number[];
  for (const row of positions) {
    for (const col of positions) {
      if (
        (row === 6 && col === 6) ||
        (row === 6 && col === size - 7) ||
        (row === size - 7 && col === 6)
      ) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          set(row + dr, col + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }
  // Reserve format information cells (values are written after the data).
  const reserveFormat = () => {
    for (let i = 0; i <= 5; i++) set(8, i, false);
    set(8, 7, false);
    set(8, 8, false);
    set(7, 8, false);
    for (let i = 9; i < 15; i++) set(14 - i, 8, false);
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, false);
    for (let i = 7; i < 15; i++) set(8, size - 15 + i, false);
    set(size - 8, 8, true); // dark module
  };
  reserveFormat();
  // Version information (version >= 7).
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      set(Math.floor(i / 3), size - 11 + (i % 3), dark);
      set(size - 11 + (i % 3), Math.floor(i / 3), dark);
    }
  }
  // Data placement (zigzag from the bottom right).
  const maskFn = MASKS[mask] as (r: number, c: number) => boolean;
  let bitIndex = 0;
  const totalBits = codewords.length * 8;
  const bitAt = (index: number) =>
    index < totalBits ? ((codewords[Math.floor(index / 8)] as number) >>> (7 - (index % 8))) & 1 : 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const col = right - j;
        const upward = ((right + 1) & 2) === 0;
        const row = upward ? size - 1 - vert : vert;
        if ((modules[row] as (boolean | null)[])[col] === null) {
          let dark = bitAt(bitIndex++) === 1;
          if (maskFn(row, col)) dark = !dark;
          (modules[row] as (boolean | null)[])[col] = dark;
        }
      }
    }
  }
  // Format information: the 15 bits are written MSB-first along both
  // strips (top-left copy, then the split copy along row/column 8).
  const format = formatBits(mask);
  const bit = (i: number) => ((format >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(8, i, bit(14 - i));
  set(8, 7, bit(8));
  set(8, 8, bit(7));
  set(7, 8, bit(6));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(14 - i));
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, bit(i));
  for (let i = 0; i < 7; i++) set(size - 7 + i, 8, bit(8 + i));
  return modules.map((row) => row.map((cell) => cell === true));
}

function penaltyScore(m: boolean[][]): number {
  const size = m.length;
  let score = 0;
  const lines: boolean[][] = [];
  for (let i = 0; i < size; i++) {
    lines.push(m[i] as boolean[]);
    lines.push(m.map((row) => row[i] as boolean));
  }
  // Rule 1: runs of >= 5 same-colour modules.
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= line.length; i++) {
      if (i < line.length && line[i] === line[i - 1]) {
        run++;
      } else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
    }
  }
  // Rule 2: 2x2 blocks of the same colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = (m[r] as boolean[])[c];
      if ((m[r] as boolean[])[c + 1] === v && (m[r + 1] as boolean[])[c] === v && (m[r + 1] as boolean[])[c + 1] === v) score += 3;
    }
  }
  // Rule 3: finder-like patterns with a 4-module light margin.
  const pattern = [true, false, true, true, true, false, true];
  for (const line of lines) {
    for (let i = 0; i + 7 <= line.length; i++) {
      let match = true;
      for (let j = 0; j < 7; j++) {
        if (line[i + j] !== pattern[j]) {
          match = false;
          break;
        }
      }
      if (!match) continue;
      const before = i >= 4 && line.slice(i - 4, i).every((v) => !v);
      const after = i + 11 <= line.length && line.slice(i + 7, i + 11).every((v) => !v);
      if (before || after) score += 40;
    }
  }
  // Rule 4: deviation of the dark ratio from 50%.
  let dark = 0;
  for (const row of m) for (const cell of row) if (cell) dark++;
  const percent = (dark * 100) / (size * size);
  const lower = Math.floor(percent / 5) * 5;
  const upper = Math.ceil(percent / 5) * 5;
  score +=
    (Math.min(Math.abs(lower - 50), Math.abs(upper - 50)) / 5) * 10;
  return score;
}

/** Encode text as a QR matrix (EC level M). Throws when the text is too long. */
export function encodeQr(text: string): QrMatrix {
  const bytes = Array.from(new TextEncoder().encode(text));
  for (let version = 1; version <= 10; version++) {
    const [, groups] = EC_TABLE[version - 1] as [number, [number, number][]];
    const totalData = groups.reduce((sum, [count, per]) => sum + count * per, 0);
    const countBits = version >= 10 ? 16 : 8;
    if (4 + countBits + bytes.length * 8 > totalData * 8) continue;
    const codewords = interleaveCodewords(dataCodewords(bytes, version), version);
    let best: boolean[][] | null = null;
    let bestScore = Number.POSITIVE_INFINITY;
    for (let mask = 0; mask < 8; mask++) {
      const matrix = buildMatrix(codewords, version, mask);
      const score = penaltyScore(matrix);
      if (score < bestScore) {
        bestScore = score;
        best = matrix;
      }
    }
    return { size: 17 + version * 4, modules: best as boolean[][] };
  }
  throw new Error("Text is too long for a version 10 QR code at level M");
}

/** Render a QR matrix as a standalone SVG document (4-module quiet zone). */
export function qrSvg(text: string, moduleSize = 8): string {
  const { size, modules } = encodeQr(text);
  const quiet = 4;
  const total = (size + quiet * 2) * moduleSize;
  let path = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if ((modules[r] as boolean[])[c]) {
        path += `M${(c + quiet) * moduleSize} ${(r + quiet) * moduleSize}h${moduleSize}v${moduleSize}h-${moduleSize}z`;
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${total}" viewBox="0 0 ${total} ${total}"><rect width="${total}" height="${total}" fill="#ffffff"/><path d="${path}" fill="#111111"/></svg>`;
}
