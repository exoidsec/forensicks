# forensicks
##  Forensicks — Full Walkthrough

**CTF by Alham Rizvi** | Difficulty: Hard | Category: Forensics + Crypto + Stego

---

## 🗂️ What You're Given

Just one file: `phantom_data.unknown`

No hints. No extension. Nothing. Let's begin.

---

## 🔵 LAYER 0 — What even IS this file?

Your first instinct should always be: *what type of file is this?*

```bash
$ file phantom_data.unknown
phantom_data.unknown: Zip archive data, at least v2.0 to extract
```

Or you can open it in a hex editor and check the **magic bytes** at the very start:

```
50 4B 03 04
```

That's the ZIP magic header! Rename and extract it:

```bash
$ mv phantom_data.unknown phantom_data.zip
$ unzip phantom_data.zip
```

You now have **6 files**:
```
fragment_1.b64
fragment_2.rot
fragment_3.rev
fragment_4.bin
README.corrupt
noise.png
```

---

## 🔵 LAYER 1 — Decode & Reassemble the Fragments

### Step 1: Read README.corrupt

The README looks damaged and messy, but read the **assembly instructions carefully**:

```
P lease note: fragments must be combined in ORDER: 1, 2, 3, 4
H ex is the intermediate format between all layers
A ll fragments decode to hex strings - join them raw
N ote that fragment 4 has damage: first 8 bytes XORed with 0xFF
T o fix fragment 4: XOR the first 8 bytes of the raw binary with 0xFF
O nce combined, the hex decodes to a Python script (it has bugs - fix them!)
M erge everything and run the script to recover the ghost_message.txt
```

👁️ **Look at the first letter of each line: P-H-A-N-T-O-M**

That's an **acrostic**. The word **PHANTOM** is hidden here. Save it — you'll need it later as a cipher key.

### Step 2: Decode each fragment

**Fragment 1 (.b64)** → Base64 encoded
```bash
$ base64 -d fragment_1.b64 > chunk1.hex
```

**Fragment 2 (.rot)** → ROT13 encoded
```bash
$ cat fragment_2.rot | tr 'A-Za-z' 'N-ZA-Mn-za-m' > chunk2.hex
```

**Fragment 3 (.rev)** → The string is reversed
```bash
$ rev fragment_3.rev > chunk3.hex
```

**Fragment 4 (.bin)** → Binary file with XOR damage on first 8 bytes
```python
data = open('fragment_4.bin', 'rb').read()
fixed = bytes([b ^ 0xFF for b in data[:8]]) + data[8:]
open('chunk4.hex', 'w').write(fixed.decode())
```

### Step 3: Reassemble & convert

Concatenate all 4 chunks in order:
```bash
$ cat chunk1.hex chunk2.hex chunk3.hex chunk4.hex > full.hex
```

Convert the hex back to readable text (it's a Python script):
```python
h = open('full.hex').read().strip()
open('ghost_decoder.py', 'w').write(bytes.fromhex(h).decode())
```

---

## 🔵 LAYER 2 — Fix the Broken Python Script

Open `ghost_decoder.py`. It's **intentionally broken** with 5 bugs. You need to find and fix all of them before it runs:

| # | Line | Bug | Fix |
|---|---|---|---|
| 1 | `for i, ch in enumrate(...)` | Typo in function name | `enumerate` |
| 2 | `k = [ord(c) for c in passphrase` | Missing closing bracket | Add `]` |
| 3 | `shift[i % len(shift)]` | Passing string as shift, not int list | Convert key chars to int offsets |
| 4 | `decrypt_message(enc key)` | Missing comma between arguments | `decrypt_message(enc, key)` |
| 5 | `with open(...) as f` | Missing colon | `with open(...) as f:` |

Once all bugs are fixed, run it:
```bash
$ python3 ghost_decoder.py
[+] Message written to ghost_message.txt
```

---

## 🔵 LAYER 3 — Vigenère Decrypt the Ghost Message

Open `ghost_message.txt`. The message looks like garbled text:

```
Wpng: Mvq Jpz FhizsMafm majy elxg ac ahr gcuhl.paz - HTT HEJL yqn ps: ta0gf_xu_tux_b01et
```

This is **Vigenère encrypted**. You already found the key back in Layer 1 — it was the acrostic: **`phantom`**

Decrypt it:
```python
def vdec(txt, key):
    res = []
    ki = 0
    for c in txt:
        if c.isalpha():
            s = ord(key[ki % len(key)].lower()) - ord('a')
            b = ord('A') if c.isupper() else ord('a')
            res.append(chr((ord(c) - b - s) % 26 + b))
            ki += 1
        else:
            res.append(c)
    return ''.join(res)

print(vdec("Wpng: Mvq Jpz FhizsMafm ...", "phantom"))
```

**Plaintext:**
```
Hint: The Uiz SoundFast your eyes on the noise.png - THE AEWS key is: gh0st_in_the_n01se
```

Two critical pieces of intel:
- 🖼️ **Look at `noise.png`**
- 🔑 **AES passphrase: `gh0st_in_the_n01se`**

---

## 🔵 LAYER 4 — Steganography + AES Decryption

### Step 1: Get the IV from PNG metadata

`noise.png` looks like pure random static — that's the point. Check its metadata first:

```python
from PIL import Image
img = Image.open('noise.png')
print(img.info)
```

In the `Description` field you'll find:
```
sensor_id=0xdeadbeefcafebabe1337f00dd00dc0de_calibrated
```

That hex string is the **AES Initialization Vector (IV)**:
```
IV = deadbeefcafebabe1337f00dd00dc0de
```

### Step 2: Extract the LSB hidden data

The encrypted vault is hidden in the **Least Significant Bit** of every pixel's RGB channels — completely invisible to the human eye:

```python
import struct
from PIL import Image

img = Image.open('noise.png').convert('RGB')
pixels = list(img.getdata())
bits = []
for px in pixels:
    for ch in px:
        bits.append(ch & 1)  # grab the LSB of each channel

# First 32 bits = length header
length = 0
for b in bits[:32]:
    length = (length << 1) | b

# Next length*8 bits = the actual data
data_bits = bits[32:32 + length * 8]
data = bytearray()
for i in range(0, len(data_bits), 8):
    byte = 0
    for b in data_bits[i:i+8]:
        byte = (byte << 1) | b
    data.append(byte)

open('vault.enc', 'wb').write(bytes(data))
```

### Step 3: AES-256-CBC Decrypt

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = hashlib.sha256(b'gh0st_in_the_n01se').digest()  # SHA256 → 32 bytes
iv  = bytes.fromhex('deadbeefcafebabe1337f00dd00dc0de')

data   = open('vault.enc', 'rb').read()
cipher = AES.new(key, AES.MODE_CBC, iv)
plain  = unpad(cipher.decrypt(data), AES.block_size)

open('vault.txt', 'wb').write(plain)
print(plain.decode())
```

`vault.txt` opens and reveals the encoding algorithm and the encoded flag.

---

## 🔵 LAYER 5 — Reverse the Custom Cipher

`vault.txt` tells you exactly how the flag was encoded (Alham left you the algorithm — but you still have to reverse it):

> 1. For each character at position `i`: `value = ASCII(char) XOR i`
> 2. Convert each value to **base-7**
> 3. Join with `:` separator
> 4. **Reverse the entire string**

So to decode, you do the exact opposite:

```python
encoded = "051:612:561:232: ..."   # from vault.txt

# Step 1: Reverse the whole string
rev = encoded[::-1]

# Step 2: Split by ':'
parts = rev.split(':')

# Step 3: Convert each from base-7 back to int
def from_base7(s):
    n = 0
    for d in s:
        n = n * 7 + int(d)
    return n

vals = [from_base7(p) for p in parts]

# Step 4: XOR each value with its position index
flag = ''.join(chr(v ^ i) for i, v in enumerate(vals))
print(flag)
```

---

## 🏁 FLAG

```
flag{ph4nt0m_4rch1v3_m4st3r_0f_l4y3rs_GG}
```

---

## 🗺️ Summary Map

```
phantom_data.unknown
        ↓ file command → it's a ZIP
    [unzip]
        ↓
  README.corrupt ──── acrostic spells "PHANTOM" (Vigenère key)
  fragment_1.b64 ──── base64 decode    ┐
  fragment_2.rot ──── ROT13 decode     ├─ join hex → fix bugs → ghost_decoder.py
  fragment_3.rev ──── reverse string   │
  fragment_4.bin ──── XOR repair       ┘
        ↓ run fixed script
  ghost_message.txt
        ↓ Vigenère decrypt (key: PHANTOM)
  → "look at noise.png, AES key: gh0st_in_the_n01se"
        ↓
  noise.png metadata ──── IV = deadbeefcafebabe...
  noise.png LSB      ──── extract → vault.enc
        ↓ AES-256-CBC decrypt
  vault.txt
        ↓ reverse custom cipher (XOR + base7 + reverse)
        ↓
flag{ph4nt0m_4rch1v3_m4st3r_0f_l4y3rs_GG} 🏁
```

Every layer builds on the last — miss one clue and you're stuck. That's what makes it a great CTF challenge! 🎭
