/**
 * Magic-byte sniffing for uploaded images. The declared Content-Type is
 * never trusted on its own: the byte signature must match the format
 * the client claims, and the stored/served type follows the signature.
 */

function ascii(bytes: Uint8Array, offset: number, text: string): boolean {
  if (bytes.length < offset + text.length) return false;
  for (let i = 0; i < text.length; i++) {
    if (bytes[offset + i] !== text.charCodeAt(i)) return false;
  }
  return true;
}

/** Returns the canonical extension for the detected format, or null. */
export function sniffImageExt(data: ArrayBuffer): string | null {
  const b = new Uint8Array(data);
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    b.length >= 8 &&
    b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
    b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a
  ) {
    return "png";
  }
  // JPEG: FF D8 FF
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    return "jpg";
  }
  // GIF: "GIF87a" / "GIF89a"
  if (ascii(b, 0, "GIF87a") || ascii(b, 0, "GIF89a")) {
    return "gif";
  }
  // WebP: "RIFF" .... "WEBP"
  if (ascii(b, 0, "RIFF") && ascii(b, 8, "WEBP")) {
    return "webp";
  }
  return null;
}
