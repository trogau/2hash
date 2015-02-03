/*
*  2hash v0.1.1 - Program to create md5 and sha1 hashes in parallel
*  http://www.crossrealm.com/2hash
*  2004-05-13
*
*  Copyright Thomas Akin (2004)
*  This work is based off of Christophe Devine's md5 and sha1 code
*  found at http://cr0.net:8040
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "stdafx.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"
#include "sha1.h"

#define VERSION "0.1.1"
#define VERSIONTEXT "Based on the original 2hash v0.1 by Thomas Akin (2004); minor modifications by David Harrison for Win32. Released under the GPL.\n"

#define MGET_UINT32(n,b,i)                      \
{                                               \
	(n) = ( (uint32) (b)[(i)    ]       )       \
	| ( (uint32) (b)[(i) + 1] <<  8 )       \
	| ( (uint32) (b)[(i) + 2] << 16 )       \
	| ( (uint32) (b)[(i) + 3] << 24 );      \
}

#define MPUT_UINT32(n,b,i)                      \
{                                               \
	(b)[(i)    ] = (uint8) ( (n)       );       \
	(b)[(i) + 1] = (uint8) ( (n) >>  8 );       \
	(b)[(i) + 2] = (uint8) ( (n) >> 16 );       \
	(b)[(i) + 3] = (uint8) ( (n) >> 24 );       \
}

#define SGET_UINT32(n,b,i)                      \
{                                               \
	(n) = ( (uint32) (b)[(i)    ] << 24 )       \
	| ( (uint32) (b)[(i) + 1] << 16 )       \
	| ( (uint32) (b)[(i) + 2] <<  8 )       \
	| ( (uint32) (b)[(i) + 3]       );      \
}

#define SPUT_UINT32(n,b,i)                      \
{                                               \
	(b)[(i)    ] = (uint8) ( (n) >> 24 );       \
	(b)[(i) + 1] = (uint8) ( (n) >> 16 );       \
	(b)[(i) + 2] = (uint8) ( (n) >>  8 );       \
	(b)[(i) + 3] = (uint8) ( (n)       );       \
}


void md5_starts( md5_context *mtx )
{
	mtx->mtotal[0] = 0;
	mtx->mtotal[1] = 0;

	mtx->mstate[0] = 0x67452301;
	mtx->mstate[1] = 0xEFCDAB89;
	mtx->mstate[2] = 0x98BADCFE;
	mtx->mstate[3] = 0x10325476;
}

void sha1_starts( sha1_context *stx )
{
	stx->stotal[0] = 0;
	stx->stotal[1] = 0;

	stx->sstate[0] = 0x67452301;
	stx->sstate[1] = 0xEFCDAB89;
	stx->sstate[2] = 0x98BADCFE;
	stx->sstate[3] = 0x10325476;
	stx->sstate[4] = 0xC3D2E1F0;
}


void md5_process( md5_context *mtx, uint8 data[64] )
{
	uint32 X[16], A, B, C, D;

	MGET_UINT32( X[0],  data,  0 );
	MGET_UINT32( X[1],  data,  4 );
	MGET_UINT32( X[2],  data,  8 );
	MGET_UINT32( X[3],  data, 12 );
	MGET_UINT32( X[4],  data, 16 );
	MGET_UINT32( X[5],  data, 20 );
	MGET_UINT32( X[6],  data, 24 );
	MGET_UINT32( X[7],  data, 28 );
	MGET_UINT32( X[8],  data, 32 );
	MGET_UINT32( X[9],  data, 36 );
	MGET_UINT32( X[10], data, 40 );
	MGET_UINT32( X[11], data, 44 );
	MGET_UINT32( X[12], data, 48 );
	MGET_UINT32( X[13], data, 52 );
	MGET_UINT32( X[14], data, 56 );
	MGET_UINT32( X[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define P(a,b,c,d,k,s,t)                                \
	{                                                       \
	a += F(b,c,d) + X[k] + t; a = S(a,s) + b;           \
	}

	A = mtx->mstate[0];
	B = mtx->mstate[1];
	C = mtx->mstate[2];
	D = mtx->mstate[3];

#define F(x,y,z) (z ^ (x & (y ^ z)))

	P( A, B, C, D,  0,  7, 0xD76AA478 );
	P( D, A, B, C,  1, 12, 0xE8C7B756 );
	P( C, D, A, B,  2, 17, 0x242070DB );
	P( B, C, D, A,  3, 22, 0xC1BDCEEE );
	P( A, B, C, D,  4,  7, 0xF57C0FAF );
	P( D, A, B, C,  5, 12, 0x4787C62A );
	P( C, D, A, B,  6, 17, 0xA8304613 );
	P( B, C, D, A,  7, 22, 0xFD469501 );
	P( A, B, C, D,  8,  7, 0x698098D8 );
	P( D, A, B, C,  9, 12, 0x8B44F7AF );
	P( C, D, A, B, 10, 17, 0xFFFF5BB1 );
	P( B, C, D, A, 11, 22, 0x895CD7BE );
	P( A, B, C, D, 12,  7, 0x6B901122 );
	P( D, A, B, C, 13, 12, 0xFD987193 );
	P( C, D, A, B, 14, 17, 0xA679438E );
	P( B, C, D, A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

	P( A, B, C, D,  1,  5, 0xF61E2562 );
	P( D, A, B, C,  6,  9, 0xC040B340 );
	P( C, D, A, B, 11, 14, 0x265E5A51 );
	P( B, C, D, A,  0, 20, 0xE9B6C7AA );
	P( A, B, C, D,  5,  5, 0xD62F105D );
	P( D, A, B, C, 10,  9, 0x02441453 );
	P( C, D, A, B, 15, 14, 0xD8A1E681 );
	P( B, C, D, A,  4, 20, 0xE7D3FBC8 );
	P( A, B, C, D,  9,  5, 0x21E1CDE6 );
	P( D, A, B, C, 14,  9, 0xC33707D6 );
	P( C, D, A, B,  3, 14, 0xF4D50D87 );
	P( B, C, D, A,  8, 20, 0x455A14ED );
	P( A, B, C, D, 13,  5, 0xA9E3E905 );
	P( D, A, B, C,  2,  9, 0xFCEFA3F8 );
	P( C, D, A, B,  7, 14, 0x676F02D9 );
	P( B, C, D, A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) (x ^ y ^ z)

	P( A, B, C, D,  5,  4, 0xFFFA3942 );
	P( D, A, B, C,  8, 11, 0x8771F681 );
	P( C, D, A, B, 11, 16, 0x6D9D6122 );
	P( B, C, D, A, 14, 23, 0xFDE5380C );
	P( A, B, C, D,  1,  4, 0xA4BEEA44 );
	P( D, A, B, C,  4, 11, 0x4BDECFA9 );
	P( C, D, A, B,  7, 16, 0xF6BB4B60 );
	P( B, C, D, A, 10, 23, 0xBEBFBC70 );
	P( A, B, C, D, 13,  4, 0x289B7EC6 );
	P( D, A, B, C,  0, 11, 0xEAA127FA );
	P( C, D, A, B,  3, 16, 0xD4EF3085 );
	P( B, C, D, A,  6, 23, 0x04881D05 );
	P( A, B, C, D,  9,  4, 0xD9D4D039 );
	P( D, A, B, C, 12, 11, 0xE6DB99E5 );
	P( C, D, A, B, 15, 16, 0x1FA27CF8 );
	P( B, C, D, A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) (y ^ (x | ~z))

	P( A, B, C, D,  0,  6, 0xF4292244 );
	P( D, A, B, C,  7, 10, 0x432AFF97 );
	P( C, D, A, B, 14, 15, 0xAB9423A7 );
	P( B, C, D, A,  5, 21, 0xFC93A039 );
	P( A, B, C, D, 12,  6, 0x655B59C3 );
	P( D, A, B, C,  3, 10, 0x8F0CCC92 );
	P( C, D, A, B, 10, 15, 0xFFEFF47D );
	P( B, C, D, A,  1, 21, 0x85845DD1 );
	P( A, B, C, D,  8,  6, 0x6FA87E4F );
	P( D, A, B, C, 15, 10, 0xFE2CE6E0 );
	P( C, D, A, B,  6, 15, 0xA3014314 );
	P( B, C, D, A, 13, 21, 0x4E0811A1 );
	P( A, B, C, D,  4,  6, 0xF7537E82 );
	P( D, A, B, C, 11, 10, 0xBD3AF235 );
	P( C, D, A, B,  2, 15, 0x2AD7D2BB );
	P( B, C, D, A,  9, 21, 0xEB86D391 );

#undef F

	mtx->mstate[0] += A;
	mtx->mstate[1] += B;
	mtx->mstate[2] += C;
	mtx->mstate[3] += D;
}

void sha1_process( sha1_context *stx, uint8 data[64] )
{
	uint32 temp, W[16], A, B, C, D, E;

	SGET_UINT32( W[0],  data,  0 );
	SGET_UINT32( W[1],  data,  4 );
	SGET_UINT32( W[2],  data,  8 );
	SGET_UINT32( W[3],  data, 12 );
	SGET_UINT32( W[4],  data, 16 );
	SGET_UINT32( W[5],  data, 20 );
	SGET_UINT32( W[6],  data, 24 );
	SGET_UINT32( W[7],  data, 28 );
	SGET_UINT32( W[8],  data, 32 );
	SGET_UINT32( W[9],  data, 36 );
	SGET_UINT32( W[10], data, 40 );
	SGET_UINT32( W[11], data, 44 );
	SGET_UINT32( W[12], data, 48 );
	SGET_UINT32( W[13], data, 52 );
	SGET_UINT32( W[14], data, 56 );
	SGET_UINT32( W[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
	(                                                       \
	temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
	W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
	( W[t & 0x0F] = S(temp,1) )                         \
	)

#define Q(a,b,c,d,e,x)                                  \
	{                                                       \
	e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
	}

	A = stx->sstate[0];
	B = stx->sstate[1];
	C = stx->sstate[2];
	D = stx->sstate[3];
	E = stx->sstate[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	Q( A, B, C, D, E, W[0]  );
	Q( E, A, B, C, D, W[1]  );
	Q( D, E, A, B, C, W[2]  );
	Q( C, D, E, A, B, W[3]  );
	Q( B, C, D, E, A, W[4]  );
	Q( A, B, C, D, E, W[5]  );
	Q( E, A, B, C, D, W[6]  );
	Q( D, E, A, B, C, W[7]  );
	Q( C, D, E, A, B, W[8]  );
	Q( B, C, D, E, A, W[9]  );
	Q( A, B, C, D, E, W[10] );
	Q( E, A, B, C, D, W[11] );
	Q( D, E, A, B, C, W[12] );
	Q( C, D, E, A, B, W[13] );
	Q( B, C, D, E, A, W[14] );
	Q( A, B, C, D, E, W[15] );
	Q( E, A, B, C, D, R(16) );
	Q( D, E, A, B, C, R(17) );
	Q( C, D, E, A, B, R(18) );
	Q( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	Q( A, B, C, D, E, R(20) );
	Q( E, A, B, C, D, R(21) );
	Q( D, E, A, B, C, R(22) );
	Q( C, D, E, A, B, R(23) );
	Q( B, C, D, E, A, R(24) );
	Q( A, B, C, D, E, R(25) );
	Q( E, A, B, C, D, R(26) );
	Q( D, E, A, B, C, R(27) );
	Q( C, D, E, A, B, R(28) );
	Q( B, C, D, E, A, R(29) );
	Q( A, B, C, D, E, R(30) );
	Q( E, A, B, C, D, R(31) );
	Q( D, E, A, B, C, R(32) );
	Q( C, D, E, A, B, R(33) );
	Q( B, C, D, E, A, R(34) );
	Q( A, B, C, D, E, R(35) );
	Q( E, A, B, C, D, R(36) );
	Q( D, E, A, B, C, R(37) );
	Q( C, D, E, A, B, R(38) );
	Q( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	Q( A, B, C, D, E, R(40) );
	Q( E, A, B, C, D, R(41) );
	Q( D, E, A, B, C, R(42) );
	Q( C, D, E, A, B, R(43) );
	Q( B, C, D, E, A, R(44) );
	Q( A, B, C, D, E, R(45) );
	Q( E, A, B, C, D, R(46) );
	Q( D, E, A, B, C, R(47) );
	Q( C, D, E, A, B, R(48) );
	Q( B, C, D, E, A, R(49) );
	Q( A, B, C, D, E, R(50) );
	Q( E, A, B, C, D, R(51) );
	Q( D, E, A, B, C, R(52) );
	Q( C, D, E, A, B, R(53) );
	Q( B, C, D, E, A, R(54) );
	Q( A, B, C, D, E, R(55) );
	Q( E, A, B, C, D, R(56) );
	Q( D, E, A, B, C, R(57) );
	Q( C, D, E, A, B, R(58) );
	Q( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	Q( A, B, C, D, E, R(60) );
	Q( E, A, B, C, D, R(61) );
	Q( D, E, A, B, C, R(62) );
	Q( C, D, E, A, B, R(63) );
	Q( B, C, D, E, A, R(64) );
	Q( A, B, C, D, E, R(65) );
	Q( E, A, B, C, D, R(66) );
	Q( D, E, A, B, C, R(67) );
	Q( C, D, E, A, B, R(68) );
	Q( B, C, D, E, A, R(69) );
	Q( A, B, C, D, E, R(70) );
	Q( E, A, B, C, D, R(71) );
	Q( D, E, A, B, C, R(72) );
	Q( C, D, E, A, B, R(73) );
	Q( B, C, D, E, A, R(74) );
	Q( A, B, C, D, E, R(75) );
	Q( E, A, B, C, D, R(76) );
	Q( D, E, A, B, C, R(77) );
	Q( C, D, E, A, B, R(78) );
	Q( B, C, D, E, A, R(79) );

#undef K
#undef F

	stx->sstate[0] += A;
	stx->sstate[1] += B;
	stx->sstate[2] += C;
	stx->sstate[3] += D;
	stx->sstate[4] += E;
}


void sha1_update( sha1_context *stx, uint8 *input, uint32 length )
{
	uint32 left, fill;

	if( ! length ) return;

	left = stx->stotal[0] & 0x3F;
	fill = 64 - left;

	stx->stotal[0] += length;
	stx->stotal[0] &= 0xFFFFFFFF;

	if( stx->stotal[0] < length )
		stx->stotal[1]++;

	if( left && length >= fill )
	{
		memcpy( (void *) (stx->sbuffer + left),
			(void *) input, fill );
		sha1_process( stx, stx->sbuffer );
		length -= fill;
		input  += fill;
		left = 0;
	}

	while( length >= 64 )
	{
		sha1_process( stx, input );
		length -= 64;
		input  += 64;
	}

	if( length )
	{
		memcpy( (void *) (stx->sbuffer + left),
			(void *) input, length );
	}
}

static uint8 sha1_padding[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sha1_finish( sha1_context *stx, uint8 digest[20] )
{
	uint32 last, padn;
	uint32 high, low;
	uint8 msglen[8];

	high = ( stx->stotal[0] >> 29 )
		| ( stx->stotal[1] <<  3 );
	low  = ( stx->stotal[0] <<  3 );

	SPUT_UINT32( high, msglen, 0 );
	SPUT_UINT32( low,  msglen, 4 );

	last = stx->stotal[0] & 0x3F;
	padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

	sha1_update( stx, sha1_padding, padn );
	sha1_update( stx, msglen, 8 );

	SPUT_UINT32( stx->sstate[0], digest,  0 );
	SPUT_UINT32( stx->sstate[1], digest,  4 );
	SPUT_UINT32( stx->sstate[2], digest,  8 );
	SPUT_UINT32( stx->sstate[3], digest, 12 );
	SPUT_UINT32( stx->sstate[4], digest, 16 );
}



void md5_update( md5_context *mtx, uint8 *input, uint32 length )
{
	uint32 left, fill;

	if( ! length ) return;

	left = mtx->mtotal[0] & 0x3F;
	fill = 64 - left;

	mtx->mtotal[0] += length;
	mtx->mtotal[0] &= 0xFFFFFFFF;

	if( mtx->mtotal[0] < length )
		mtx->mtotal[1]++;

	if( left && length >= fill )
	{
		memcpy( (void *) (mtx->mbuffer + left),
			(void *) input, fill );
		md5_process( mtx, mtx->mbuffer );
		length -= fill;
		input  += fill;
		left = 0;
	}

	while( length >= 64 )
	{
		md5_process( mtx, input );
		length -= 64;
		input  += 64;
	}

	if( length )
	{
		memcpy( (void *) (mtx->mbuffer + left),
			(void *) input, length );
	}
}

static uint8 md5_padding[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void md5_finish( md5_context *mtx, uint8 digest[16] )
{
	uint32 last, padn;
	uint32 high, low;
	uint8 msglen[8];

	high = ( mtx->mtotal[0] >> 29 )
		| ( mtx->mtotal[1] <<  3 );
	low  = ( mtx->mtotal[0] <<  3 );

	MPUT_UINT32( low,  msglen, 0 );
	MPUT_UINT32( high, msglen, 4 );

	last = mtx->mtotal[0] & 0x3F;
	padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

	md5_update( mtx, md5_padding, padn );
	md5_update( mtx, msglen, 8 );

	MPUT_UINT32( mtx->mstate[0], digest,  0 );
	MPUT_UINT32( mtx->mstate[1], digest,  4 );
	MPUT_UINT32( mtx->mstate[2], digest,  8 );
	MPUT_UINT32( mtx->mstate[3], digest, 12 );
}


//int _tmain(int argc, _TCHAR* argv[])
int  main( int argc, char *argv[] )
{
	FILE *f;
	int n, i, j;
	int read_stdin = 0;
	md5_context mtx;
	sha1_context stx;
	unsigned char buf[1000];
	unsigned char md5sum[16];
	unsigned char sha1sum[20];  

	// If we're running in STDIN input mode...
	if (argc == 1)
	{
		read_stdin = 1;
		argv[1] = "-";
		argc++;
	}

	if (strcmp(argv[1], "-h") == 0)
	{
		printf("usage: 2hash.exe [filename]\n");
		return 0;
	}

	if (strcmp(argv[1], "-v") == 0)
	{
		printf("2hash.exe version %s\n", VERSION);
		printf("%s", VERSIONTEXT);
		return 0;
	}

	for (n = 1; n < argc; n++) 
	{
		if (read_stdin) 
		{
			f = stdin;
		}
		else
		{
			f = fopen(argv[n], "rb");
		}

		if( f != NULL)
		{

			md5_starts  ( &mtx );
			sha1_starts ( &stx);

			while( ( i = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
			{
				md5_update  ( &mtx, buf, i );
				sha1_update ( &stx, buf, i);
			}

			md5_finish  ( &mtx, md5sum );
			sha1_finish ( &stx, sha1sum);

			//printf ("md5: ");
			for( j = 0; j < 16; j++ )
			{
				printf( "%02x", md5sum[j] );
			}
			printf(" | ");
			//printf( "          %s\n", argv[n] );

			//printf ("sha1: ");
			for( j = 0; j < 20; j++ )
			{
				printf( "%02x", sha1sum[j] );
			}
			printf("\n");


			//printf( "  %s\n", argv[n] );
		} else {
			fprintf(stderr, "%s: %s: No such file or directory\n", argv[0], argv[n]);
		}
		if (read_stdin) 
		{
			fclose (stdin);
		} 
		else 
		{
			fclose (f);
		}
	}
	return( 0 );
}
