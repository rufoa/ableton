import argparse
import re
from random import randint

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA1

EDITIONS = {
    "Lite": 4,
    "Intro": 3,
    "Standard": 0,
    "Suite": 2,
}

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--hwid", help="Your hardware code", required=True)
parser.add_argument("-o", "--output", help="Authorization file", default="Authorize.auz")
parser.add_argument("-v", "--version", help="Ableton Live version", type=int, choices=range(9, 13), default=12)
parser.add_argument("-e", "--edition", help="Ableton Live edition", type=str.capitalize, choices=EDITIONS, default="Suite")
args = parser.parse_args()


def construct_key(*, p, q, g, y, x) -> dsa.DSAPrivateKey:
    params = dsa.DSAParameterNumbers(p, q, g)
    pub = dsa.DSAPublicNumbers(y, params)
    priv = dsa.DSAPrivateNumbers(x, pub)
    return priv.private_key(backend=default_backend())


def sign(k: dsa.DSAPrivateKey, m: str) -> str:
    """P1363 format sig over m as a string of hex digits"""
    assert k.key_size == 1024
    sig = k.sign(m.encode(), SHA1())
    r, s = decode_dss_signature(sig)
    return "{:040X}{:040X}".format(r, s)


def fix_group_checksum(group_number: int, n: int) -> int:
    checksum = n >> 4 & 0xf ^ \
               n >> 5 & 0x8 ^ \
               n >> 9 & 0x7 ^ \
               n >> 11 & 0xe ^ \
               n >> 15 & 0x1 ^ \
               group_number
    return n & 0xfff0 | checksum


def overall_checksum(groups: list[int]) -> int:
    r = 0
    for i in range(20):
        g, digit = divmod(i, 4)
        v = groups[g] >> (digit * 8) & 0xff
        # v is lowbyte, highbyte, 0, 0 in turn for each group
        r ^= v << 8
        for _ in range(8):
            r <<= 1
            if r & 0x10000:
                r ^= 0x8005
    return r & 0xffff


def random_serial():
    """
    3xxc-xxxc-xxxc-xxxc-xxxc-dddd
    x is random
    c is a checksum over each group
    d is a checksum over all groups
    """
    groups = [randint(0x3000, 0x3fff),
              randint(0x0000, 0xffff),
              randint(0x0000, 0xffff),
              randint(0x0000, 0xffff),
              randint(0x0000, 0xffff)]
    for i in range(5):
        groups[i] = fix_group_checksum(i, groups[i])
    d = overall_checksum(groups)
    return "{:04X}-{:04X}-{:04X}-{:04X}-{:04X}-{:04X}".format(*groups, d)


def generate_single(k: dsa.DSAPrivateKey, id1: int, id2: int, hwid: str) -> str:
    f = "{},{:02X},{:02X},Standard,{}"
    serial = random_serial()
    msg = f.format(serial, id1, id2, hwid)
    sig = sign(k, msg)
    return f.format(serial, id1, id2, sig)


def generate_all(k: dsa.DSAPrivateKey, edition: str, version: int, hwid: str) -> str:
    yield generate_single(k, EDITIONS[edition], version << 4, hwid)
    for i in range(0x40, 0xff + 1):
        yield generate_single(k, i, 0x10, hwid)
    for i in range(0x8000, 0x80ff + 1):
        yield generate_single(k, i, 0x10, hwid)


team_r2r_key = construct_key(
    p=0xbab5a10970f083e266a1252897daac1d67374712e79d3df1bc8c08a3493c6aa9a2ff33be4513d8b6767ab6aae2af6cc9107976fa75fee134e8b7be03d78cc64e089c845207d306a6035f172c5b750275f00bd3ca2331b8a59d54fe79393854dd884b8d334d553b38bc5e886c0a2dd0e4ec32f7d88de1a7c9df5c424ee7b1ce6d,
    q=0xc37be90e3f8e64e03a42ca8d68ad5c83eb47d3a9,
    g=0xa33c8737f42e2516a1525544e611d71295805ced94d260d5777db976f6721f52479158e2477efb0ea6ff30d34d15b23669f0967d29a2c746288ee42c8d91fe4dbe79a73ee8831251a3566864858e589adcd41c3863ea118fbbcdf34bd64ef0e7ae20b00192709a8346c816b54a51d804a6e06fce1da4b043c2b5270d4e441622,
    y=0x33fd12fd459fe6c5c1bc0991e915f8bf49997716bde5c3bdf9a096bdcbf7a425ef6a495683cc84f3dafab7a1d5cf9f377fda84c042e47e7c608298c6917a3caab40b3c6262559fe699091c5bb6ac8de01f0a9f887c739ffa3a1a858000f85a1811ec33a2190063341e8c20aba068b90383f8ca27d30aa89adf40de9ce735dedb,
    x=0xc369ea757b46484d1df3819cc4183f6f9a9bcf3c
)

hwid = args.hwid.upper()
if len(hwid) == 24:
    hwid = "-".join(hwid[i:i+4] for i in range(0, 24, 4))
assert re.fullmatch(r"([0-9A-F]{4}-){5}[0-9A-F]{4}", hwid), f"Expected hardware ID like 1111-1111-1111-1111-1111-1111, not {hwid}"

lines = generate_all(team_r2r_key, args.edition, args.version, hwid)
with open(args.output, mode="w", newline="\n") as f:
    f.write("\n".join(lines))
