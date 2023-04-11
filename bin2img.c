/*
 * Copyright (C) 2014 Charles Manning <cdhmanning@gmail.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 * Reference doc http://www.altera.com.cn/literature/hb/cyclone-v/cv_5400A.pdf
 * Note this doc is not entirely accurate. Of particular interest to us is the
 * "header" length field being in U32s and not bytes.
 *
 * "Header" is a structure of the following format.
 * this is positioned at 0x40.
 *
 * Endian is LSB.
 *
 * Offset   Length   Usage
 * -----------------------
 *   0x40        4   Validation word 0x31305341
 *   0x44        1   Version (whatever, zero is fine)
 *   0x45        1   Flags   (unused, zero is fine)
 *   0x46        2   Length  (in units of u32, including the end checksum).
 *   0x48        2   Zero
 *   0x4A        2   Checksum over the header. NB Not CRC32
 *
 * At the end of the code we have a 32-bit CRC checksum over whole binary
 * excluding the CRC.
 *
 * Note that the CRC used here is **not** the zlib/Adler crc32. It is the
 * CRC-32 used in bzip2, ethernet and elsewhere.
 *
 * The image is padded out to 64k, because that is what is
 * typically used to write the image to the boot medium.
 */

#include "stdint.h"
//#include <iostream>
#include "pbl_crc32.h"
#include "string.h"
#include "stdio.h"
#include <stdlib.h> 

#define HEADER_OFFSET	    0x40
#define VALIDATION_WORD	    0x31305341
#define PADDED_SIZE	        0x10000

 /* To allow for adding CRC, the max input size is a bit smaller. */
#define MAX_INPUT_SIZE	(PADDED_SIZE - sizeof(uint32_t))


static uint8_t buffer[PADDED_SIZE];

static struct socfpga_header 
{
	uint32_t validation;
	uint8_t  version;
	uint8_t  flags;
	uint16_t length_u32;
	uint16_t zero;
	uint16_t checksum;
} header;

/*
 * The header checksum is just a very simple checksum over
 * the header area.
 * There is still a crc32 over the whole lot.
 */
static uint16_t hdr_checksum(struct socfpga_header* header)
{
	int len = sizeof(*header) - sizeof(header->checksum);
	uint8_t* buf = (uint8_t*)header;
	uint16_t ret = 0;

	while (--len)
		ret += *buf++;

	return ret;
}


static void build_header(uint8_t* buf, uint8_t version, uint8_t flags,
	uint16_t length_bytes)
{
	//header.validation = cpu_to_le32(VALIDATION_WORD);
	header.validation = VALIDATION_WORD;
	header.version = version;
	header.flags = flags;
	//header.length_u32 = cpu_to_le16(length_bytes / 4);
	header.length_u32 = length_bytes / 4;
	header.zero = 0;
	//header.checksum = cpu_to_le16(hdr_checksum(&header));
	header.checksum = hdr_checksum(&header);

	memcpy(buf, &header, sizeof(header));
}

/*
 * Perform a rudimentary verification of header and return
 * size of image.
 */
static int verify_header(const uint8_t* buf)
{
	memcpy(&header, buf, sizeof(header));

	//if (le32_to_cpu(header.validation) != VALIDATION_WORD)		return -1;
	if (header.validation != VALIDATION_WORD)						return -1;
	//if (le16_to_cpu(header.checksum) != hdr_checksum(&header))	return -1;
	if (header.checksum != hdr_checksum(&header))					return -1;

	//return le16_to_cpu(header.length_u32) * 4;
	return header.length_u32 * 4;
}

/* Sign the buffer and return the signed buffer size */
static int sign_buffer(uint8_t* buf,
	uint8_t version, uint8_t flags,
	int len, int pad_64k)
{
	uint32_t calc_crc;

	/* Align the length up */
	len = (len + 3) & (~3);

	/* Build header, adding 4 bytes to length to hold the CRC32. */
	build_header(buf + HEADER_OFFSET, version, flags, len + 4);

	/* Calculate and apply the CRC */
	calc_crc = ~pbl_crc32(0, (char*)buf, len);

	//*((uint32_t*)(buf + len)) = cpu_to_le32(calc_crc);
	*((uint32_t*)(buf + len)) = calc_crc;

	if (!pad_64k)
		return len + 4;

	return PADDED_SIZE;
}

/* Verify that the buffer looks sane */
static int verify_buffer(const uint8_t* buf)
{
	int len; /* Including 32bit CRC */
	uint32_t calc_crc;
	uint32_t buf_crc;

	len = verify_header(buf + HEADER_OFFSET);
	if (len < 0) {
		printf("Invalid header\n");
		return -1;
	}

	if (len < HEADER_OFFSET || len > PADDED_SIZE) {
		printf("Invalid header length (%i)\n", len);
		return -1;
	}

	/*
	 * Adjust length to the base of the CRC.
	 * Check the CRC.
	*/
	len -= 4;

	calc_crc = ~pbl_crc32(0, (const char*)buf, len);

	//buf_crc = le32_to_cpu(*((uint32_t*)(buf + len)));
	buf_crc = *((uint32_t*)(buf + len));

	if (buf_crc != calc_crc) 
	{
		fprintf(stderr, "CRC32 does not match (%08x != %08x)\n",
			buf_crc, calc_crc);
		return -1;
	}

	return 0;
}

/* mkimage glue functions */
static int socfpgaimage_verify_header(unsigned char* ptr, int image_size,
	struct image_tool_params* params)
{
	if (image_size != PADDED_SIZE)
		return -1;

	return verify_buffer(ptr);
}

//static void socfpgaimage_print_header(const void* ptr)
//{
//	if (verify_buffer((const uint8_t *)ptr) == 0)
//		printf("Looks like a sane SOCFPGA preloader\n");
//	else
//		printf("Not a sane SOCFPGA preloader\n");
//}

//static int socfpgaimage_check_params(struct image_tool_params* params)
//{
//	/* Not sure if we should be accepting fflags */
//	return	(params->dflag && (params->fflag || params->lflag)) ||
//		(params->fflag && (params->dflag || params->lflag)) ||
//		(params->lflag && (params->dflag || params->fflag));
//}

//static int socfpgaimage_check_image_types(uint8_t type)
//{
//	if (type == IH_TYPE_SOCFPGAIMAGE)
//		return EXIT_SUCCESS;
//	return EXIT_FAILURE;
//}

/*
 * To work in with the mkimage framework, we do some ugly stuff...
 *
 * First, socfpgaimage_vrec_header() is called.
 * We prepend a fake header big enough to make the file PADDED_SIZE.
 * This gives us enough space to do what we want later.
 *
 * Next, socfpgaimage_set_header() is called.
 * We fix up the buffer by moving the image to the start of the buffer.
 * We now have some room to do what we need (add CRC and padding).
 */

//static int data_size;
//#define FAKE_HEADER_SIZE (PADDED_SIZE - data_size)
//
//static int socfpgaimage_vrec_header(struct image_tool_params* params,
//	struct image_type_params* tparams)
//{
//	struct stat sbuf;
//
//	if (params->datafile &&
//		stat(params->datafile, &sbuf) == 0 &&
//		sbuf.st_size <= MAX_INPUT_SIZE) {
//		data_size = sbuf.st_size;
//		tparams->header_size = FAKE_HEADER_SIZE;
//	}
//	return 0;
//}

static void socfpgaimage_set_header(void* ptr, uint32_t data_size)
{
	#define FAKE_HEADER_SIZE (PADDED_SIZE - data_size)
	uint8_t* buf = (uint8_t*)ptr;

	/*
	 * This function is called after vrec_header() has been called.
	 * At this stage we have the FAKE_HEADER_SIZE dummy bytes followed by
	 * data_size image bytes. Total = PADDED_SIZE.
	 * We need to fix the buffer by moving the image bytes back to
	 * the beginning of the buffer, then actually do the signing stuff...
	 */
//	memmove(buf, buf + FAKE_HEADER_SIZE, data_size);
	memset(buf + data_size, 0, FAKE_HEADER_SIZE);

	sign_buffer(buf, 0, 0, data_size, 0);
}


int main(int argc, char* argv[])
{
	#define DEFAULT_INPUT_FILENAME		"myBoot.bin"
	#define	DEFAULT_OUTPUT_FILENAME		"myBoot.img"
	#define	SIZEOF_FILENAME				256

	uint8_t*	ucBuffer				=NULL;
	uint32_t	uiSize					=0;
	FILE*		myFile					=0;
	FILE*		myOutputFile			=0;
	uint8_t*	ucOriginalBuffer		=NULL;
	char		caInputFileName[SIZEOF_FILENAME];
	char		caOutputFileName[SIZEOF_FILENAME];

	sprintf_s(caInputFileName,	SIZEOF_FILENAME, DEFAULT_INPUT_FILENAME);
	sprintf_s(caOutputFileName, SIZEOF_FILENAME, DEFAULT_OUTPUT_FILENAME);

	if (argc >= 2)       // 1er argument (optionnel) est le fichier d'entree 
	{
		printf("argv[1]     = %s\n",	argv[1]);
		printf("argv[1] len = %d\n",	strlen(argv[1]));
		memset(caInputFileName, 0, SIZEOF_FILENAME);
		strncpy_s(caInputFileName, SIZEOF_FILENAME, argv[1], strlen(argv[1]));
	}

	if (argc >= 3)       // 2eme argument (optionnel) est le fichier de sortie
	{
		printf("argv[2]     = %s\n", argv[2]);
		printf("argv[2] len = %d\n", strlen(argv[2]));
		memset(caOutputFileName, 0, SIZEOF_FILENAME);
		strncpy_s(caOutputFileName, SIZEOF_FILENAME, argv[2], strlen(argv[2]));
	}

	// to do - here check input file presence


	fopen_s(&myFile, caInputFileName, "rb");
	if (myFile == NULL)	return -1;
	fseek(myFile, 0, SEEK_END);
	uiSize = ftell(myFile);
	fseek(myFile, 0, SEEK_SET);
	ucBuffer = (uint8_t*)malloc(PADDED_SIZE);
	fread(ucBuffer, 1, uiSize, myFile);
	ucOriginalBuffer = ucBuffer;
	fclose(myFile);

	socfpgaimage_set_header(ucBuffer, uiSize);

	fopen_s(&myOutputFile, caOutputFileName, "wb");
	fwrite(ucOriginalBuffer, 1, PADDED_SIZE, myOutputFile);
	fwrite(ucOriginalBuffer, 1, PADDED_SIZE, myOutputFile);
	fwrite(ucOriginalBuffer, 1, PADDED_SIZE, myOutputFile);
	fwrite(ucOriginalBuffer, 1, PADDED_SIZE, myOutputFile);
	fclose(myOutputFile);

	free(ucBuffer);
}

