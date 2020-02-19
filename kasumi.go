package kasumi

import (
	"fmt"
	"math/bits"
)

/*-----------------------------------------------------------------------
 *						kasumi.c
 *-----------------------------------------------------------------------
 *
 *	A sample implementation of KASUMI, the core algorithm for the
 *	3GPP Confidentiality and Integrity algorithms.
 *
 *	Version 1.1		08 May 2000
 *
 *-----------------------------------------------------------------------*/
type REGISTER32 uint32
type REGISTER16 uint16
type REGISTER64 uint64

var KLi1, KLi2, KOi1, KOi2, KOi3, KIi1, KIi2, KIi3 [8]uint16

func FI(in uint16, subkey uint16) uint16 {
	var nine, seven uint16
	var S7 = [128]uint16{
		54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
		55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
		53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
		20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
		117, 116, 76, 11, 89, 106, 0, 125, 118, 99, 86, 69, 30, 57, 126, 87,
		112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35, 103, 32, 97, 28, 66,
		102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
		64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3}
	var S9 = [512]uint16{
		167, 239, 161, 379, 391, 334, 9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
		183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
		175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
		95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
		165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
		501, 407, 249, 265, 89, 186, 221, 428, 164, 74, 440, 196, 458, 421, 350, 163,
		232, 158, 134, 354, 13, 250, 491, 142, 191, 69, 193, 425, 152, 227, 366, 135,
		344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,
		487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
		475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
		363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
		439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
		465, 416, 252, 287, 246, 6, 83, 305, 420, 345, 153, 502, 65, 61, 244, 282,
		173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195, 430, 49, 79, 166, 330,
		280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
		132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,
		35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
		50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
		72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
		185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
		1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
		336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
		47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
		414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
		266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
		311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
		485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
		312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
		284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
		97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
		438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
		43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461}

	nine = uint16(in >> 7)
	seven = uint16(in & 0x7F)

	nine = uint16(S9[nine] ^ seven)
	seven = uint16(S7[seven] ^ (nine & 0x7F))

	seven ^= (subkey >> 9)
	nine ^= (subkey & 0x1FF)

	nine = uint16(S9[nine] ^ seven)
	seven = uint16(S7[seven] ^ (nine & 0x7F))

	in = uint16((seven << 9) + nine)

	return (in)
}

func FO(in uint32, index int) uint32 {
	var left, right uint16
	left = uint16(in >> 16)
	right = uint16(in)
	left ^= KOi1[index]
	left = FI(left, KIi1[index])
	left ^= right

	right ^= KOi2[index]
	right = FI(right, KIi2[index])
	right ^= left

	left ^= KOi3[index]
	left = FI(left, KIi3[index])
	left ^= right

	return (uint32(right) << 16) + uint32(left)
}

func FL(in uint32, index int) uint32 {
	var l, r, a, b uint16
	l = uint16(in >> 16)
	r = uint16(in)
	a = uint16(l & KLi1[index])
	r ^= bits.RotateLeft16(a, 1)

	b = uint16(r | KLi2[index])
	l ^= bits.RotateLeft16(b, 1)
	return ((uint32(l)) << 16) + uint32(r)
}

func getU32(d []byte) uint32 {
	return (uint32(d[0]) << 24) | (uint32(d[1]) << 16) | (uint32(d[2]) << 8) | uint32(d[3])
}

func htonl(d uint32) uint32 {
	return ((d >> 24) & 0xff) | ((d>>16)&0xff)<<8 | ((d>>8)&0xff)<<16 | ((d & 0xff) << 24)
}

// kasumi main algorithm
func kasumi(data uint64) uint64 {
	right := (uint32(data & 0xffffffff))
	left := (uint32(data >> 32))
	n := 0
	for {
		temp := FL(left, n)
		temp = FO(temp, n)
		n++
		right ^= temp
		temp = FO(right, n)
		temp = FL(temp, n)
		n++
		left ^= temp
		if n > 7 {
			break
		}
	}
	data = uint64((left>>24)&0xff) << 56
	data |= uint64((right>>24)&0xff) << 24
	data |= uint64((left>>16)&0xff) << 48
	data |= uint64((right>>16)&0xff) << 16
	data |= uint64((left>>8)&0xff) << 40
	data |= uint64((right>>8)&0xff) << 8
	data |= uint64((left)&0xff) << 32
	data |= uint64(right & 0xff)
	return data
}

func getU16(d []byte) uint16 {
	return (uint16(d[0]) << 8) | uint16(d[1])
}

// KeySchedule builds the key schedule
func KeySchedule(k []byte) {
	var C = []uint16{0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210}
	var key, Kprime [8]uint16
	for n := 0; n < 8; n++ {
		key[n] = getU16(k[n*2:])
	}
	for n := 0; n < 8; n++ {
		Kprime[n] = uint16(key[n] ^ C[n])
	}
	for n := 0; n < 8; n++ {
		KLi1[n] = bits.RotateLeft16(key[n], 1)
		KLi2[n] = Kprime[(n+2)&0x7]
		KOi1[n] = bits.RotateLeft16(key[(n+1)&0x7], 5)
		KOi2[n] = bits.RotateLeft16(key[(n+5)&0x7], 8)
		KOi3[n] = bits.RotateLeft16(key[(n+6)&0x7], 13)
		KIi1[n] = Kprime[(n+4)&0x7]
		KIi2[n] = Kprime[(n+3)&0x7]
		KIi3[n] = Kprime[(n+7)&0x7]
	}
}

/*-------------------------------------------------------------------
*				F8 - Confidentiality Algorithm
*-------------------------------------------------------------------
*
*	A sample implementation of f8, the 3GPP Confidentiality algorithm.
*
*	Version 1.0		05 November  1999
*
*-------------------------------------------------------------------*/

func getByte32(d uint32, bit int) byte {
	return byte(d>>bit) & 0xff
}

// Kasumi_f8 encrypts the provided data using the 3GPP EA1
func Kasumi_f8(key []byte, count, bearer, dir uint32, data []byte, length int) []byte {
	var A uint64
	lastbits := (8 - (length % 8)) % 8
	var ModKey []byte = make([]byte, 16)
	var blkcnt uint16

	var temp uint64
	A = 0

	A = uint64(count) << 32
	A |= uint64(bearer) << 27
	A |= uint64(dir) << 26

	var n int
	for n = 0; n < 16; n++ {
		ModKey[n] = byte(key[n] ^ 0x55)
	}
	KeySchedule(ModKey)

	A = kasumi(A)
	blkcnt = 0
	pos := 0
	KeySchedule(key)

	for length > 0 {
		temp ^= A
		temp ^= uint64(blkcnt & 0xff)
		temp ^= uint64(blkcnt) >> 8

		temp = kasumi(temp)

		if length >= 64 {
			n = 8
		} else {
			n = (length + 7) / 8
		}

		for i := 0; i < n; i++ {
			data[pos] ^= byte(temp >> ((7 - i) * 8))
			pos++
		}

		length -= 64
		blkcnt++
	}
	if lastbits > 0 {
		pos--
	}
	data[pos] &= byte(int(0x100) - (1 << lastbits))
	return data
}

/*-------------------------------------------------------------------
*				F9 - Integrity Algorithm
*-------------------------------------------------------------------
*
*	A sample implementation of f9, the 3GPP Integrity algorithm.
*
*	Version 1.1		05 September  2000
*
*-------------------------------------------------------------------*/
func dump64(name string, d uint64) {
	fmt.Printf("dump64: %s - ", name)
	for a := 0; a < 8; a++ {
		fmt.Printf("%02X ", ((d >> (a * 8)) & 0xff))
	}
	fmt.Print("\n")
}

func dump32(name string, d uint32) {
	fmt.Printf("dump32: %s - ", name)
	for a := 0; a < 4; a++ {
		fmt.Printf("%02X ", ((d >> (a * 8)) & 0xff))
	}
	fmt.Print("\n")
}

func dump(name string, d []byte) {
	fmt.Printf("dump: %s - ", name)
	for a := 0; a < len(d); a++ {
		fmt.Printf("%02X ", d[a])
	}
	fmt.Print("\n")
}

// Kasumi_f9 provides the EIA1 3GPP integrity dword (16bit)
func Kasumi_f9(key []byte, count, fresh, dir uint32, data []byte, length int) uint32 {
	var A uint64
	ModKey := make([]byte, 16)

	KeySchedule(key)
	for n := 0; n < 4; n++ {
		A |= uint64(count>>(24-(n*8))) & 0xff << ((7 - n) * 8)
		A |= uint64(fresh>>(24-(n*8))) & 0xff << ((3 - n) * 8)
	}
	A = kasumi(A)
	B := A
	pos := 0
	for length >= 64 {
		for n := 0; n < 8; n++ {
			A ^= uint64(data[pos]) << ((7 - n) * 8)
			pos++
		}
		A = kasumi(A)
		length -= 64
		B ^= A
	}
	n := 0
	for length >= 8 {
		A ^= uint64(data[pos]) << ((7 - n) * 8)
		pos++
		n++
		length -= 8
	}
	var i byte
	if length > 0 {
		i = data[pos]
		if dir != 0 {
			i |= 1 << (7 - length)
		}
	} else {
		if dir == 0 {
			i = 0
		} else {
			i = 0x80
		}
	}
	A ^= uint64(i) << ((7 - n) * 8)
	n++

	if (length == 7) && (n == 8) {
		A = kasumi(A)
		B ^= A
		A ^= 0x8000000000000000
		n = 1
	} else {
		if length == 7 {
			A ^= 0x80 << (7 - n)
		} else {
			bit := uint64(1 << (6 - length))
			A ^= bit << ((8 - n) * 8)
		}
	}

	A = kasumi(A)
	B ^= A
	pos = 0
	for n := 0; n < 16; n++ {
		ModKey[n] = byte(key[pos]) ^ 0xAA
		pos++
	}
	KeySchedule(ModKey)
	B = kasumi(B)
	return uint32(B >> 32)
}

/*-----------------------------------------------------------
*			e n d    o f    f 9 . c
*-----------------------------------------------------------*/
