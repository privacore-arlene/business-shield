/** Screenshot validation: real file signature, never the declared data-URL prefix. */
import { MAX_IMAGE_BYTES } from "./types";

export type ImageVerdict = { ok: true; mime: string } | { ok: false; code: string };

export function validateImage(image: unknown): ImageVerdict {
  if (typeof image !== "string") return { ok: false, code: "image_invalid" };
  const match = /^data:([a-z0-9.+/-]+);base64,([A-Za-z0-9+/=]+)$/i.exec(image.trim());
  if (!match) return { ok: false, code: "image_invalid" };
  const declared = (match[1] ?? "").toLowerCase();
  const b64 = match[2] ?? "";
  if (!["image/png", "image/jpeg", "image/webp"].includes(declared)) {
    return { ok: false, code: "image_type" };
  }
  const padding = b64.match(/=+$/)?.[0].length ?? 0;
  const bytes = Math.floor((b64.length * 3) / 4) - padding;
  if (bytes <= 0) return { ok: false, code: "image_invalid" };
  if (bytes > MAX_IMAGE_BYTES) return { ok: false, code: "image_too_large" };

  let head: Uint8Array;
  try {
    head = new Uint8Array(Buffer.from(b64.slice(0, 32), "base64"));
  } catch {
    return { ok: false, code: "image_invalid" };
  }
  const is = (offset: number, sig: number[]) => sig.every((b, i) => head[offset + i] === b);
  let actual: string | null = null;
  if (is(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) actual = "image/png";
  else if (is(0, [0xff, 0xd8, 0xff])) actual = "image/jpeg";
  else if (is(0, [0x52, 0x49, 0x46, 0x46]) && is(8, [0x57, 0x45, 0x42, 0x50])) actual = "image/webp";

  if (!actual) return { ok: false, code: "image_signature" };
  if (actual !== declared) return { ok: false, code: "image_mismatch" };
  return { ok: true, mime: actual };
}