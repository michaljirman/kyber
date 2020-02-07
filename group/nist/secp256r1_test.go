package nist

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestSecp256r1(t *testing.T) {
	d, _ := hex.DecodeString("20837f75fefdbb1335ab756c2111d9e043d0ea6cf78e4d492c73a7c9f7b25c413252b06d94097df85f94dfc415553b01a6de671b106f9981028c789e01926b99")
	wrappedKey, _ := hex.DecodeString("0100777cdfcd9856f9bfb58a37935090aff951d3b5f17a92680689a28e830c62a1c830834ec4b28441e80d5aa7416e92d470e951ab6601346f0daed893f4ed0cd721dbbf9c486a8cb7cc02d06e11efb15645bc")
	// expectedUnwrappedKey, _ := hex.DecodeString("f1d720a4f9e3882a65fed326edf1e3e4")

	buf := bytes.NewReader(wrappedKey)
	wkeySizeBytes := make([]byte, 2)
	binary.Read(buf, binary.BigEndian, &wkeySizeBytes)
	wkeySize := (binary.BigEndian.Uint16(wkeySizeBytes) + 7) / 8
	t.Log(wkeySize)

	wkey := make([]byte, wkeySize)
	binary.Read(buf, binary.BigEndian, &wkey)
	t.Logf("wkey: %x", wkey)

	xValue := new(big.Int)
	xValue.SetBytes(wkey)
	curve := NewSecp256r1()
	curve.Init()
	x, y := curve.ComputeY(xValue)
	sX, sY := curve.ScalarMult(x, y, d)

	t.Logf("%v\n", sX)
	t.Logf("%v\n", sY)

	// zb = S[0] # x value
	// zb_bytes = (zb).to_bytes(32, byteorder='big')
	// self.logger.debug("zb: %s" % binascii.hexlify(zb_bytes))
	// digest = hashlib.sha256()
	// digest.update(b"\x00\x00\x00\x01")
	// digest.update(zb_bytes)
	// # Params
	// digest.update(self.formatted_curve_Oid)
	// digest.update(self.public_key_alg_id)
	// digest.update(b"\x03")
	// digest.update(b"\x01")
	// digest.update(self.kdf_hash_id)
	// digest.update(self.sym_alg_id)
	// digest.update(self.anonymous_sender)
	// digest.update(self.fingerprint)
	// hash = digest.digest()
	// self.logger.debug("hash: %s" % binascii.hexlify(hash))

	// xValue.SetString("47296783185661199165341240533112758755410393422946914354458143042232219001255", 10)
	// yValueExpected := new(big.Int)
	// yValueExpected.SetString("52202467873416172242036070718129493917438678414441997191071755831796099934360", 10)
	// yValueExpected.SetString("52202467873416172242036070718129493917438678414441997191071755831796099934360", 10)

	// t.Logf("%v\n", yValueExpected)

	// if yValue.Cmp(yValueExpected) != 0 {
	// 	t.Fatal("unexpected y")
	// }

	// def unwrap(self, wrapped_key, d):
	//     cur_pos = 0
	//     wkey_size = int((struct.unpack(">H", wrapped_key[cur_pos:2])[0] + 7) / 8)
	//     cur_pos += 2
	//     wkey = struct.unpack(">%ds" % wkey_size, wrapped_key[cur_pos:cur_pos+wkey_size])[0]
	//     cur_pos += wkey_size
	//     wrapped_size = struct.unpack(">B", wrapped_key[cur_pos:cur_pos+1])[0]
	//     cur_pos += 1
	//     wrapped = struct.unpack(">%ds" % wrapped_size, wrapped_key[cur_pos:cur_pos+wrapped_size])[0]

	//     Q = self.decode_point(wkey)
	//     if Q is None:
	//         raise Exception('Q ec point cannot be empty.')
	//     S = scalar_mult(d, Q)
	//     hash = self.apply(S)
	//     derived_key = struct.unpack(">%ds" % self.sym_alg_id_length, hash[0:self.sym_alg_id_length])[0]

	//     # RFC3394WrapEngine
	//     # Either wrapped[32+36:]  or wrapped
	//     # from crypto.aeswrap import AESUnwrap
	//     # unwrapped = AESUnwrap(derived_key, wrapped)
	//     unwrapped = aes_unwrap_key(derived_key, wrapped)
	//     # self.logger.debug("unwrapped: %s" % binascii.hexlify(unwrapped))

	//     # data
	//         # 1byte sym_alg_id || decrypted bytes || 2byte checksum || padding
	//     # finalize, verify padding PKCS5, checksum
	//     padding_size = struct.unpack(">B", unwrapped[-1:])[0]
	//     # self.logger.debug("padding_size: %s" % padding_size)
	//     if padding_size <= 0 or padding_size > len(unwrapped) - 3:
	//         raise Exception("bad padding length")

	//     i = len(unwrapped)-1
	//     while i > len(unwrapped) - padding_size:
	//         if unwrapped[i] != padding_size:
	//             raise Exception("bad padding")
	//         i -= 1

	//     i -= 2
	//     expected_checksum = struct.unpack(">H", unwrapped[i:i+2])[0]
	//     # self.logger.debug("expected_checksum: %s" % expected_checksum)

	//     decrypted_data_checksum = 0
	//     while i > 1:
	//         i -= 1
	//         decrypted_data_checksum += struct.unpack(">B", unwrapped[i:i+1])[0]

	//     if decrypted_data_checksum & 0xffff != expected_checksum:
	//         raise Exception("bad checksum")

	//     # Remove sym_alg_id + padding
	//     key = unwrapped[1:len(unwrapped) - padding_size - 2]

}
