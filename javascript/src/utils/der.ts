import type { Bytes } from './encoding';

export class DerReader {
  private offset = 0;

  constructor(private readonly bytes: Bytes) {}

  eof(): boolean {
    return this.offset >= this.bytes.length;
  }

  private readByte(): number {
    if (this.offset >= this.bytes.length) throw new Error('DER: out of range');
    return this.bytes[this.offset++]!;
  }

  private readLength(): number {
    const first = this.readByte();
    if ((first & 0x80) === 0) return first;
    const numBytes = first & 0x7f;
    if (numBytes === 0) throw new Error('DER: indefinite length not supported');
    let len = 0;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | this.readByte();
    return len;
  }

  private readValue(tag: number): Bytes {
    const actual = this.readByte();
    if (actual !== tag) throw new Error(`DER: expected tag 0x${tag.toString(16)}, got 0x${actual.toString(16)}`);
    const len = this.readLength();
    const start = this.offset;
    const end = start + len;
    if (end > this.bytes.length) throw new Error('DER: length out of range');
    this.offset = end;
    return this.bytes.slice(start, end);
  }

  readSequence(): DerReader {
    const content = this.readValue(0x30);
    return new DerReader(content);
  }

  readIntegerBytes(): Bytes {
    return this.readValue(0x02);
  }

  readOctetString(): Bytes {
    return this.readValue(0x04);
  }

  readBitString(): { unusedBits: number; data: Bytes } {
    const content = this.readValue(0x03);
    if (content.length === 0) throw new Error('DER: invalid BIT STRING');
    const unusedBits = content[0]!;
    return { unusedBits, data: content.slice(1) };
  }

  readOID(): string {
    const content = this.readValue(0x06);
    if (content.length === 0) throw new Error('DER: empty OID');
    const first = content[0]!;
    const parts: number[] = [Math.floor(first / 40), first % 40];
    let value = 0;
    for (let i = 1; i < content.length; i++) {
      const b = content[i]!;
      value = (value << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join('.');
  }

  readContextSpecific(tagNumber: number): DerReader {
    const tag = 0xa0 + tagNumber;
    const content = this.readValue(tag);
    return new DerReader(content);
  }

  peekTag(): number {
    if (this.offset >= this.bytes.length) throw new Error('DER: out of range');
    return this.bytes[this.offset]!;
  }

  skipAny(): void {
    this.readByte();
    const len = this.readLength();
    this.offset += len;
    if (this.offset > this.bytes.length) throw new Error('DER: length out of range');
  }
}
