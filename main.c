/*
 * nupacker: A tool for packing all images to nuwriter format.
 *
 * Copyright (C) qianfan Zhao <qianfanguijin@163.com>
 * License under GPL.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libgen.h>

#define NUPACKER_VERSION	"1.04"
#define PACK_ALIGN		(64 * 1024)
#define ALIGN(s, a)		(((s) + (a) - 1) / (a) * (a))
#define ALIGNED_LENGTH(x)	ALIGN(x, PACK_ALIGN)

/* pre-declares */
struct image;
static int load_image_env(struct image *img);
static int uboot_env_is_valid(const uint8_t *e, size_t len);

#define u32_little_endian(a, b, c, d) ( 			\
				(((a) & 0xff) <<  0) |		\
				(((b) & 0xff) <<  8) |		\
				(((c) & 0xff) << 16) |		\
				(((d) & 0xff) << 24) 		\
				)
#define put_u32_little_endian(p, u) do {			\
				*p++ = ((u) >>  0) & 0xff;	\
				*p++ = ((u) >>  8) & 0xff;	\
				*p++ = ((u) >> 16) & 0xff;	\
				*p++ = ((u) >> 24) & 0xff;	\
} while (0)

static const unsigned int crctab32[] = {
	0x00000000U, 0x77073096U, 0xee0e612cU, 0x990951baU, 0x076dc419U,
	0x706af48fU, 0xe963a535U, 0x9e6495a3U, 0x0edb8832U, 0x79dcb8a4U,
	0xe0d5e91eU, 0x97d2d988U, 0x09b64c2bU, 0x7eb17cbdU, 0xe7b82d07U,
	0x90bf1d91U, 0x1db71064U, 0x6ab020f2U, 0xf3b97148U, 0x84be41deU,
	0x1adad47dU, 0x6ddde4ebU, 0xf4d4b551U, 0x83d385c7U, 0x136c9856U,
	0x646ba8c0U, 0xfd62f97aU, 0x8a65c9ecU, 0x14015c4fU, 0x63066cd9U,
	0xfa0f3d63U, 0x8d080df5U, 0x3b6e20c8U, 0x4c69105eU, 0xd56041e4U,
	0xa2677172U, 0x3c03e4d1U, 0x4b04d447U, 0xd20d85fdU, 0xa50ab56bU,
	0x35b5a8faU, 0x42b2986cU, 0xdbbbc9d6U, 0xacbcf940U, 0x32d86ce3U,
	0x45df5c75U, 0xdcd60dcfU, 0xabd13d59U, 0x26d930acU, 0x51de003aU,
	0xc8d75180U, 0xbfd06116U, 0x21b4f4b5U, 0x56b3c423U, 0xcfba9599U,
	0xb8bda50fU, 0x2802b89eU, 0x5f058808U, 0xc60cd9b2U, 0xb10be924U,
	0x2f6f7c87U, 0x58684c11U, 0xc1611dabU, 0xb6662d3dU, 0x76dc4190U,
	0x01db7106U, 0x98d220bcU, 0xefd5102aU, 0x71b18589U, 0x06b6b51fU,
	0x9fbfe4a5U, 0xe8b8d433U, 0x7807c9a2U, 0x0f00f934U, 0x9609a88eU,
	0xe10e9818U, 0x7f6a0dbbU, 0x086d3d2dU, 0x91646c97U, 0xe6635c01U,
	0x6b6b51f4U, 0x1c6c6162U, 0x856530d8U, 0xf262004eU, 0x6c0695edU,
	0x1b01a57bU, 0x8208f4c1U, 0xf50fc457U, 0x65b0d9c6U, 0x12b7e950U,
	0x8bbeb8eaU, 0xfcb9887cU, 0x62dd1ddfU, 0x15da2d49U, 0x8cd37cf3U,
	0xfbd44c65U, 0x4db26158U, 0x3ab551ceU, 0xa3bc0074U, 0xd4bb30e2U,
	0x4adfa541U, 0x3dd895d7U, 0xa4d1c46dU, 0xd3d6f4fbU, 0x4369e96aU,
	0x346ed9fcU, 0xad678846U, 0xda60b8d0U, 0x44042d73U, 0x33031de5U,
	0xaa0a4c5fU, 0xdd0d7cc9U, 0x5005713cU, 0x270241aaU, 0xbe0b1010U,
	0xc90c2086U, 0x5768b525U, 0x206f85b3U, 0xb966d409U, 0xce61e49fU,
	0x5edef90eU, 0x29d9c998U, 0xb0d09822U, 0xc7d7a8b4U, 0x59b33d17U,
	0x2eb40d81U, 0xb7bd5c3bU, 0xc0ba6cadU, 0xedb88320U, 0x9abfb3b6U,
	0x03b6e20cU, 0x74b1d29aU, 0xead54739U, 0x9dd277afU, 0x04db2615U,
	0x73dc1683U, 0xe3630b12U, 0x94643b84U, 0x0d6d6a3eU, 0x7a6a5aa8U,
	0xe40ecf0bU, 0x9309ff9dU, 0x0a00ae27U, 0x7d079eb1U, 0xf00f9344U,
	0x8708a3d2U, 0x1e01f268U, 0x6906c2feU, 0xf762575dU, 0x806567cbU,
	0x196c3671U, 0x6e6b06e7U, 0xfed41b76U, 0x89d32be0U, 0x10da7a5aU,
	0x67dd4accU, 0xf9b9df6fU, 0x8ebeeff9U, 0x17b7be43U, 0x60b08ed5U,
	0xd6d6a3e8U, 0xa1d1937eU, 0x38d8c2c4U, 0x4fdff252U, 0xd1bb67f1U,
	0xa6bc5767U, 0x3fb506ddU, 0x48b2364bU, 0xd80d2bdaU, 0xaf0a1b4cU,
	0x36034af6U, 0x41047a60U, 0xdf60efc3U, 0xa867df55U, 0x316e8eefU,
	0x4669be79U, 0xcb61b38cU, 0xbc66831aU, 0x256fd2a0U, 0x5268e236U,
	0xcc0c7795U, 0xbb0b4703U, 0x220216b9U, 0x5505262fU, 0xc5ba3bbeU,
	0xb2bd0b28U, 0x2bb45a92U, 0x5cb36a04U, 0xc2d7ffa7U, 0xb5d0cf31U,
	0x2cd99e8bU, 0x5bdeae1dU, 0x9b64c2b0U, 0xec63f226U, 0x756aa39cU,
	0x026d930aU, 0x9c0906a9U, 0xeb0e363fU, 0x72076785U, 0x05005713U,
	0x95bf4a82U, 0xe2b87a14U, 0x7bb12baeU, 0x0cb61b38U, 0x92d28e9bU,
	0xe5d5be0dU, 0x7cdcefb7U, 0x0bdbdf21U, 0x86d3d2d4U, 0xf1d4e242U,
	0x68ddb3f8U, 0x1fda836eU, 0x81be16cdU, 0xf6b9265bU, 0x6fb077e1U,
	0x18b74777U, 0x88085ae6U, 0xff0f6a70U, 0x66063bcaU, 0x11010b5cU,
	0x8f659effU, 0xf862ae69U, 0x616bffd3U, 0x166ccf45U, 0xa00ae278U,
	0xd70dd2eeU, 0x4e048354U, 0x3903b3c2U, 0xa7672661U, 0xd06016f7U,
	0x4969474dU, 0x3e6e77dbU, 0xaed16a4aU, 0xd9d65adcU, 0x40df0b66U,
	0x37d83bf0U, 0xa9bcae53U, 0xdebb9ec5U, 0x47b2cf7fU, 0x30b5ffe9U,
	0xbdbdf21cU, 0xcabac28aU, 0x53b39330U, 0x24b4a3a6U, 0xbad03605U,
	0xcdd70693U, 0x54de5729U, 0x23d967bfU, 0xb3667a2eU, 0xc4614ab8U,
	0x5d681b02U, 0x2a6f2b94U, 0xb40bbe37U, 0xc30c8ea1U, 0x5a05df1bU,
	0x2d02ef8dU
};

#define cpu_to_le32(a) (a)
#define le32_to_cpu(a) (a)
#define DO_CRC(x) crc = tab[(crc ^ (x)) & 255] ^ (crc >> 8)

uint32_t crc32_no_comp(uint32_t crc, const uint8_t *buf, size_t len)
{
	const uint32_t *tab = crctab32;
	const uint32_t *b =(const uint32_t *)buf;
	size_t rem_len;

	crc = cpu_to_le32(crc);
	/* Align it */
	if (((long)b) & 3 && len) {
		uint8_t *p = (uint8_t *)b;
		do {
			DO_CRC(*p++);
		} while ((--len) && ((long)p)&3);
		b = (uint32_t *)p;
	}

	rem_len = len & 3;
	len = len >> 2;
	for (--b; len; --len) {
		/* load data 32 bits wide, xor data 32 bits wide. */
		crc ^= *++b; /* use pre increment for speed */
		DO_CRC(0);
		DO_CRC(0);
		DO_CRC(0);
		DO_CRC(0);
	}
	len = rem_len;
	/* And the last few bytes */
	if (len) {
		uint8_t *p = (uint8_t *)(b + 1) - 1;
		do {
			DO_CRC(*++p); /* use pre increment for speed */
		} while (--len);
	}

	return le32_to_cpu(crc);
}

static uint32_t crc32 (uint32_t crc, const uint8_t *p, size_t len)
{
	return crc32_no_comp(crc ^ 0xffffffffL, p, len) ^ 0xffffffffL;
}

#define MEDIA_TYPE_SRAM				0
#define MEDIA_TYPE_NAND				3
#define MEDIA_TYPE_EMMC				5
#define MEDIA_TYPE_SPI				7
#define MEDIA_TYPE_NOT_SELECTED			255

#define EMMC_SECTOR_SIZE			512

static void usage(void)
{
	fprintf(stderr, "nupacker -i pack.bin: Show packed image's information\n");
	fprintf(stderr, "nupacker -pack\n");
	fprintf(stderr, "         -ddr which_dir/ddr.ini\n");
	fprintf(stderr, "         -spl which_dir/u-boot-spl.bin@0,exec=0x200\n");
	fprintf(stderr, "         -env which_dir/env.txt@0x80000,size=0x10000\n");
	fprintf(stderr, "         [-data which_dir/u-boot.bin@0x100000]\n");
	fprintf(stderr, "         [-data which_dir/uImage_dtb.bin@0x200000]\n");
	fprintf(stderr, "         [-data which_dir/rootfs.ubi@0x800000]\n");
	fprintf(stderr, "         -o which_dir/pack.bin: Pack images\n");
	fprintf(stderr, "nupacker -pack -f nupacker.cfg -o which_dir/pack.bin\n");
	fprintf(stderr, "  Loading images from config file and pack them.\n");
	fprintf(stderr, "nupacker -E which_dir/pack.bin [-O dir]: Extract packed image\n");
	fprintf(stderr, "nupacker -g [-media=emmc ]\n");
	fprintf(stderr, "         -ddr which_dir/ddr.ini\n");
	fprintf(stderr, "         -spl which_dir/u-boot-spl.bin@0,exec=0x200\n");
	fprintf(stderr, "         -o which_dir/u-boot-spl-ddr.bin\n");
	fprintf(stderr, "  Glue ddr and uboot\n");
	fprintf(stderr, "nupacker -ddr ddr.ini/ddr.bin [-o outfile]:\n");
	fprintf(stderr, "  Translate ddr configuration between ini and bin\n");
	fprintf(stderr, "  Write translated data to stdout default\n");
	fprintf(stderr, "nupacker -env env.bin/env.txt/env.env [-o outfile]:\n");
	fprintf(stderr, "  Translate env between bin and txt\n");
	fprintf(stderr, "  Write translated data to stdout default\n");
	fprintf(stderr, "VERSION: %s\n", NUPACKER_VERSION);
}

/*
 * Global variables used for parser main's command line params.
 */
static const char *opt_extract_file = NULL;
static const char *opt_out_dir = NULL, *opt_out = NULL;
static char opt_ddr[128] = { 0 };
static int opt_media_type = MEDIA_TYPE_NOT_SELECTED;
static int opt_glue_ddr_spl = 0;
static int opt_ignore_env_crc = 0;
static int opt_extract = 0, opt_pack = 0;
#define OUT_DIR (!opt_out_dir ? "." : opt_out_dir)

static long file_length(FILE *fp)
{
	long length;

	fseek(fp, 0, SEEK_END);
	length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return length;
}

static char *load_alloc_file(const char *filename, const char *flag, long *length)
{
	FILE *fp = fopen(filename, flag);
	char *m = NULL;

	if (!fp) {
		fprintf(stderr, "Open %s failed: %m\n", filename);
		return m;
	}

	long l = file_length(fp);
	if (! (m = malloc(sizeof(char) * l))) {
		fprintf(stderr, "Failed to alloc %ld bytes memory.\n", l);
		goto _done;
	}
	fread(m, 1, l, fp);
	*length = l;

_done:
	fclose(fp);
	return m;
}

static int check_file_suffix(const char *file, const char *suffix)
{
	if (strlen(file) > strlen(suffix)) {
		const char *s = &file[strlen(file) - strlen(suffix)];

		if (!strncmp(s, suffix, strlen(suffix)))
			return 0;
	}

	return -1;
}

/*
 * Translate ddr configuration file.
 * Binary format:
 * 55 AA 55 AA + item number(4 Bytes) + items + padding
 */
static const uint32_t ddr_bin_header = 0xaa55aa55;

static char *translate_ddr_ini(const char *f_ini, long *length)
{
	FILE *fp_ini = fopen(f_ini, "r");
	char *p, *bin = NULL;
	int size, items = 0;

	if (!fp_ini) {
		fprintf(stderr, "Open %s failed: %m\n", f_ini);
		return NULL;
	}

	for (int i = 0; i < 2; i++) {
		unsigned int addr, value;

		while (!feof(fp_ini)) {
			/* format: 0xB0000220=0x01000000 */
			if (fscanf(fp_ini, "0x%X=0x%X\n", &addr, &value) != 2) {
				fprintf(stderr, "Parse %s failed in %d lines\n",
						f_ini, items + 1);
				if (bin) {
					free(bin);
					bin = NULL;
				}
				goto _done;
			}

			if (i == 0) { /* The first time scan each line */
				++items;
			} else { /* The second time translate to binary */
				put_u32_little_endian(p, addr);
				put_u32_little_endian(p, value);
			}
		}

		if (i == 0) { /* Parse done, alloc memory */
			size = sizeof(ddr_bin_header) + 4 + items * 8;
			size = ALIGN(size, 16);

			if (!(bin = malloc(size))) {
				fprintf(stderr, "No enough memory\n");
				goto _done;
			}

			/* clean data and padding */
			memset(bin, 0, size);

			p = bin;
			put_u32_little_endian(p, ddr_bin_header);
			put_u32_little_endian(p, items);
		}

		fseek(fp_ini, 0, SEEK_SET);
	}
	*length = size;

_done:
	fclose(fp_ini);
	return bin;
}

static int translate_ddr_ini2bin(const char *f_ini, const char *f_bin)
{
	long length = 0;
	char *bin;
	int ret = -1;

	if ((bin = translate_ddr_ini(f_ini, &length))) {
		FILE *fp_out = stdout;

		if (f_bin && !(fp_out = fopen(f_bin, "wb+"))) {
			fprintf(stderr, "Open/Create %s failed: %m\n", f_bin);
		} else {
			fwrite(bin, 1, length, fp_out);
			ret = 0;
		}

		if (f_bin)
			fclose(fp_out);
		free(bin);
	}

	return ret;
}

static int _translate_ddr_bin2ini(const uint8_t *bin, long length, const char *f_ini)
{
	FILE *fp_ini = !f_ini ? stdout : fopen(f_ini, "w+");
	int i = 0, items = 0, ret = -1;
	const char *p;

	if (!fp_ini) {
		fprintf(stderr, "Open/Create %s failed: %m", f_ini);
		return ret;
	}

	uint32_t header = u32_little_endian(bin[0], bin[1], bin[2], bin[3]);
	if (header != ddr_bin_header) {
		fprintf(stderr, "Invalid header: %X\n", header);
		goto _close;
	}

	items = u32_little_endian(bin[4], bin[5], bin[6], bin[7]);
	long l = items * 8 + sizeof(ddr_bin_header) + 4;
	if (l > length) {
		fprintf(stderr, "Length too larger: %X%X%X%X\n", bin[4],
				bin[5], bin[6], bin[7]);
		goto _close;
	}

	for (i = 0, p = bin + 8; i < items; i++, p += 8) {
		unsigned int addr = u32_little_endian(p[0], p[1], p[2], p[3]);
		unsigned int val  = u32_little_endian(p[4], p[5], p[6], p[7]);

		fprintf(fp_ini, "0x%08X=0x%08X\n", addr, val);
	}
	ret = 0;

_close:
	fclose(fp_ini);
	return ret;
}

static int translate_ddr_bin2ini(const char *in, const char *out)
{
	long length = 0;
	uint8_t *bin;

	bin = load_alloc_file(in, "rb", &length);
	if (bin) {
		int ret = _translate_ddr_bin2ini(bin, length, out);
		free(bin);
		return ret;
	}

	return -1;
}

static int translate_ddr(const char *in, const char *out)
{
	if (!check_file_suffix(in, ".bin"))
		return translate_ddr_bin2ini(in, out);
	else if (!check_file_suffix(in, "ini"))
		return translate_ddr_ini2bin(in, out);

	fprintf(stderr, "Unknow ddr config file type: %s\n", in);
	return -1;
}

struct image {
	int			image_type;
	uint32_t		exec_addr;
	uint32_t		location;
	char			filename[FILENAME_MAX];
	char			*binary;
	long			length;
	long			partition_size;
};

static int parse_image_param(const char *param, struct image *img)
{
	char *at, *exec, *size, *endp = NULL;
	uint32_t location, exec_addr, sz;
	const char *filename_endp;

	/* which_dir/u-boot-spl.bin@0,exec=0x200 or
	 * which_dir/u-boot.bin@0x100000 or
	 * which_dir/env.txt@0x80000,size=0x10000 or
	 * which_dir/env.txt,size=65536
	 */
	at = strstr(param, "@");
	if (at) {
		location = (uint32_t)strtoul(at + 1, &endp, 16);
		if (*endp != '\0' && *endp != ',') {
			fprintf(stderr, "Parse location failed: %s\n", param);
			return -1;
		}
		img->location = location;
	}

	if ((exec = strstr(param, "exec="))) {
		exec_addr = (uint32_t)strtoul(exec + 5, &endp, 16);
		if (*endp != '\0') {
			fprintf(stderr, "Parse exec failed: %s\n", param);
			return -1;
		}
		img->exec_addr = exec_addr;
	}

	if ((size = strstr(param, "size="))) {
		/* auto detect dec or hex format */
		sz = (uint32_t)strtoul(size + 5, &endp, 0);
		if (*endp != '\0') {
			fprintf(stderr, "Parse size failed: %s\n", param);
			return -1;
		}
		img->partition_size = sz;
	}

	/* copy filename */
	if (at)
		filename_endp = at;
	else if (strstr(param, ","))
		filename_endp = strstr(param, ",");
	else
		filename_endp = param + strlen(param);

	for (int i = 0; i < filename_endp - param; i++)
		img->filename[i] = param[i];

	return 0;
}

static int saveenv_bin2txt(uint8_t *env, const char *outfile)
{
	uint8_t *data = env + sizeof(uint32_t); /* skip CRC */
	FILE *fp = stdout;
	int len;

	if (data[0] == 0 || data[0] == 1) {
		/* skip env flags: active/obsolete flags ENVF_REDUND_ */
		data++;
	}

	if (outfile) {
		fp = fopen(outfile, "w+");
		if (!fp) {
			fprintf(stderr, "Open %s for w+ failed: %m\n", outfile);
			return -1;
		}
	}

	while ((len = strlen(data)) > 0) {
		int esc_newline = 0;
		char *p = data;
		char *next;

		while ((next = strchr(p, '\n'))) {
			/* replace '\n' in this string line to "\n" */
			*next = '\0';

			fprintf(fp, "%s\\n\n", p);
			p = next + 1;
		}
		fprintf(fp, "%s\n", p);

		/* skip string and '\0' */
		data += len;
		data += 1;
	}

	fclose(fp);

	return 0;
}

static int translate_env_bin2txt(struct image *env, const char *out)
{
	env->binary = load_alloc_file(env->filename, "rb", &env->length);
	if (!env->binary)
		return -1;

	if (!opt_ignore_env_crc) {
		if (!uboot_env_is_valid(env->binary, env->length)) {
			fprintf(stderr, "ENV checksum doesn't match\n");
			return -1;
		}
	}

	return saveenv_bin2txt(env->binary, out);
}

static int translate_env_txt2bin(struct image *env, const char *out)
{
	int ret = load_image_env(env);
	FILE *fp = stdout;

	if (ret < 0)
		return ret;

	if (out) {
		fp = fopen(out, "wb+");
		if (!fp) {
			fprintf(stderr, "Open %s for wb+ failed\n", out);
			return -1;
		}
	}

	fwrite(env->binary, env->length, 1, fp);
	return 0;
}

static int translate_image_env(struct image *env, const char *out)
{
	const char *name = env->filename;

	if (!check_file_suffix(name, ".bin") || !check_file_suffix(name, ".img"))
		return translate_env_bin2txt(env, out);
	else if (!check_file_suffix(name, ".txt") || !check_file_suffix(name, ".env"))
		return translate_env_txt2bin(env, out);

	fprintf(stderr, "Unknow env config file type: %s\n", name);
	return -1;
}

/*
 * Nuwriter Pack Image Format:
 * 1. pack_header
 * 2. pack_child_header + pack_spl_header + ddr + spl
 * 3. pack_child_header + image 1
 * 4. pack_child_header + image 2
 * 5. pack_child_header + image n
 */

#define	PACK_ACTION					5

struct pack_header {
	uint32_t		action_flag;
	uint32_t		aligned_length;
	uint32_t		image_number;
	uint32_t		reserved;
};

enum {
	IMAGE_TYPE_DATA, IMAGE_TYPE_ENV, IMAGE_TYPE_SPL,
	IMAGE_TYPE_PACK, IMAGE_TYPE_IMAGE,
	IMAGE_TYPE_DATA_OOB, IMAGE_TYPE_INVALAID,
};

#define image_type_is_valid(t)				\
	((t) >= IMAGE_TYPE_DATA && (t) < IMAGE_TYPE_INVALAID)

static const char *str_img_type[] = {
	[IMAGE_TYPE_SPL]	= "SPL ",
	[IMAGE_TYPE_DATA]	= "DATA",
	[IMAGE_TYPE_DATA_OOB]	= "OOB ",
	[IMAGE_TYPE_ENV]	= "ENV ",
	[IMAGE_TYPE_IMAGE]	= "IMAG",
	[IMAGE_TYPE_PACK]	= "PACK",
};

struct pack_child_header {
	uint32_t		file_length;
	uint32_t		location;
	uint32_t		image_type;
	uint32_t		reserved;
};

#define SPL_HEADER_MAGIC				0x4e565420 /* TVN */

struct pack_spl_header {
	uint32_t		magic;
	uint32_t		exe_addr;
	uint32_t		spl_file_length;
	uint32_t		reserved;
};

/*
 * Load image file to memory.
 * Glue u-boot-spl.bin and ddr configurations as IMAGE_TYPE_SPL.
 */
static int load_image_spl(struct image *img)
{
	long glue_length, ddr_length, spl_length;
	struct pack_spl_header header;
	char *ddr, *spl;

	ddr = translate_ddr_ini(opt_ddr, &ddr_length);
	spl = load_alloc_file(img->filename, "rb", &spl_length);

	if (ddr && spl) {
		glue_length = ddr_length + spl_length + sizeof(header);

		if ((img->binary = malloc(glue_length))) {
			header.magic = SPL_HEADER_MAGIC;
			header.spl_file_length = spl_length;
			header.exe_addr = img->exec_addr;
			header.reserved = (uint32_t)-1;
			img->length = glue_length;

			memcpy(img->binary, &header, sizeof(header));
			memcpy(img->binary + sizeof(header), ddr, ddr_length);
			memcpy(img->binary + sizeof(header) + ddr_length,
				spl, spl_length);
		}
	}

	free(spl);
	free(ddr);

	return 0;
}

/*
 * loading env.txt and convert to u-boot env binary format.
 */
static int load_image_env(struct image *img)
{
	FILE *fp = fopen(img->filename, "r");
	uint8_t *crc, *env, *p;
	uint32_t c32;

	if (!fp) {
		fprintf(stderr, "Open %s failed: %m\n", img->filename);
		return -1;
	}

	img->binary = malloc(img->partition_size);
	if (!img->binary) {
		fprintf(stderr, "alloc memory for env failed: size = %ld\n",
			img->partition_size);
		fclose(fp);
		return -1;
	}

	crc = (uint8_t *)img->binary;
	p = env = (uint8_t *)(img->binary + sizeof(c32));
	memset(img->binary, 0, img->partition_size);

	while (1) {
		char line[16384] = { 0 };
		int line_ending = 1;
		int n;

		if (!fgets(line, sizeof(line) - 1, fp))
			break;

		n = strlen(line);
		/* skip blank line */
		if (n == 1 && line[0] == '\n')
			continue;

		/* make sure env format is linux style, we don't care '\r' */
		if (line[n - 1] == '\n') {
			line[n - 1] = '\0';
			n--;
		}

		/* replace string "\n" to '\n' */
		if (n >= 2 && line[n - 2] == '\\' && line[n - 1] == 'n') {
			line[n - 2] = '\n';
			line_ending = 0;
			n--;
		}

		/* copy lines and adding a '\0' */
		memcpy(p, line, n);
		p += n;
		p += line_ending;
	}

	c32 = crc32(0, env, img->partition_size - sizeof(c32));
	put_u32_little_endian(crc, c32);
	img->length = img->partition_size;

	fclose(fp);
	return 0;
}

static int load_image(struct image *img)
{
	img->binary = NULL;
	img->length = 0;

	switch (img->image_type) {
	case IMAGE_TYPE_SPL:
		load_image_spl(img);
		break;
	case IMAGE_TYPE_ENV:
		if (!img->partition_size) {
			fprintf(stderr, "Partition ENV's size is not defined.\n");
			return -1;
		}
		load_image_env(img);
		break;
	default:
		img->binary = load_alloc_file(img->filename, "rb",
					      &img->length);
		break;
	}

	return (img->binary && img->length > 0) ? 0 : -1;
}

static int nupacker_config_file_append(int is_append, const char *fmt, ...)
{
	char config[128] = { 0 };
	va_list arg;
	FILE *fp;

	snprintf(config, sizeof(config), "%s/nupacker.cfg", OUT_DIR);
	fp = fopen(config, is_append ? "a+" : "w+");
	if (!fp) {
		fprintf(stderr, "open %s failed: %m\n", config);
		return -1;
	}

	va_start(arg, fmt);
	vfprintf(fp, fmt, arg);
	va_end(arg);

	fclose(fp);
	return 0;
}

/*
 * Save the unextraced spl into file.
 */
static int save_child_spl_ddr(const uint8_t *ddr, int ddr_length)
{
	char file[128] = { 0 };

	snprintf(file, sizeof(file), "%s/ddr.ini", OUT_DIR);
	nupacker_config_file_append(1, "-ddr %s\n", file);

	return _translate_ddr_bin2ini(ddr, ddr_length, file);
}

static int save_child_spl_spl(struct pack_spl_header *header,
			      const uint8_t *spl, int spl_length)
{
	char file[128] = { 0 };
	FILE *fp;

	/* spl image is always location at 0x0 */
	snprintf(file, sizeof(file), "%s/spl.bin", OUT_DIR);
	nupacker_config_file_append(1, "-spl %s@0x0,exec=0x%x\n",
				    file, header->exe_addr);

	fp = fopen(file, "wb+");
	if (!fp) {
		fprintf(stderr, "Open %s failed: %m\n", file);
		return -1;
	}

	fwrite(spl, 1, spl_length, fp);
	fclose(fp);

	return 0;
}

static int save_child_spl(struct pack_spl_header *spl, int ddr_length,
			  int spl_length)
{
	const char *data = (const char *)(spl + 1);

	if (!save_child_spl_ddr(data, ddr_length)) {
		if (!save_child_spl_spl(spl, data + ddr_length, spl_length))
			return 0;
	}

	return -1;
}

static int save_child(struct pack_child_header *child)
{
	const char *data = (const char *)(child + 1);
	char save_file[128];

	if (opt_extract) {
		snprintf(save_file, sizeof(save_file), "%s/0x%x.bin",
			 OUT_DIR, child->location);
		nupacker_config_file_append(1, "-data %s@0x%x\n",
					    save_file, child->location);

		FILE *fp = fopen(save_file, "wb+");
		if (!fp) {
			fprintf(stderr, "Open %s failed: %m\n", save_file);
			return -1;
		}

		fwrite(data, 1, child->file_length, fp);
		fclose(fp);
	}

	return 0;
}

static int uboot_env_is_valid(const uint8_t *e, size_t len)
{
	uint32_t c32 = u32_little_endian(e[0], e[1], e[2], e[3]);
	uint32_t c;

	c = crc32(0, e + sizeof(c), len - sizeof(c));
	return c == c32;
}

static int save_child_env(struct pack_child_header *child)
{
	uint8_t *env = (uint8_t *)(child + 1);
	char name[32] = { 0 };

	if (!uboot_env_is_valid(env, child->file_length)) {
		fprintf(stderr, "Waring: ENV is bad, droping...\n");
		return 0;
	}

	snprintf(name, sizeof(name), "%s/0x%x.env", OUT_DIR, child->location);
	nupacker_config_file_append(1, "-env %s@0x%x,size=0x%x\n",
				    name, child->location, child->file_length);

	return saveenv_bin2txt(env, name);
}

static int extract_child(struct pack_child_header *child)
{
	struct pack_spl_header *spl = (struct pack_spl_header *)(child + 1);
	int spl_length, ddr_length;

	switch (child->image_type) {
	case IMAGE_TYPE_SPL:
		if (spl->magic != SPL_HEADER_MAGIC) {
			fprintf(stderr, "Invalid SPL header magic: %08x\n",
				spl->magic);
			return -1;
		}

		spl_length = spl->spl_file_length;
		ddr_length = child->file_length - spl_length - sizeof(*spl);

		printf("Found DDR configures, size = %d\n", ddr_length);
		printf("Found %s @ 0x%08x, exec = 0x%x, size = %d\n",
			str_img_type[child->image_type],
			child->location, spl->exe_addr, spl_length);

		return save_child_spl(spl, ddr_length, spl_length);
	case IMAGE_TYPE_ENV:
		printf("Found %s @ 0x%08x, size = %ld\n",
			str_img_type[child->image_type], child->location,
			(long)child->file_length);
		return save_child_env(child);
		break;
	default:
		printf("Found %s @ 0x%08x, size = %ld\n",
			str_img_type[child->image_type],
			child->location, (long)child->file_length);

		if (save_child(child) < 0)
			return -1;
		break;
	}

	return 0;
}

static int extract_packed_image(const char *packed_image, long length)
{
	struct pack_header *header = (struct pack_header *)packed_image;
	int images_number = (int)header->image_number;
	const char *bounds = packed_image + length;

	packed_image += sizeof(*header);
	if (header->action_flag != PACK_ACTION) {
		fprintf(stderr, "Invalid action flag: %08x\n",
			header->action_flag);
		return -1;
	}

	if (nupacker_config_file_append(0,
	    "# This file is auto generated by nupacker.\n"
	    "# version: %s\n",
	    NUPACKER_VERSION) < 0) {
		return -1;
	}

	while (images_number-- > 0) {
		struct pack_child_header *child =
				(struct pack_child_header *)packed_image;

		if (image_type_is_valid(child->image_type)) {
			if (extract_child(child) < 0)
				return -1;
		} else {
			fprintf(stderr, "Unknow image type: %d, offset = %ld\n",
				child->image_type,
				(void *)child - (void *)header);
			return -1;
		}

		const char *next = packed_image + sizeof(*child) + child->file_length;
		if (next <= bounds) {
			packed_image = next;
		} else {
			fprintf(stderr, "Image out of bounds\n");
			return -1;
		}
	}


	return 0;
}

static int extract_packed_image_file(const char *packed)
{
	long l_packed_image = 0;

	char *packed_image = load_alloc_file(packed, "rb", &l_packed_image);
	if (!packed_image)
		return -1;

	int ret = extract_packed_image(packed_image, l_packed_image);
	free(packed_image);

	return ret;
}

static int pack_images(struct image *imgs, int img_num)
{
	FILE *out_pack = fopen(opt_out, "wb+");
	uint32_t aligned_length = 0;

	struct pack_header header;
	struct image *img;
	int n;

	if (!out_pack) {
		fprintf(stderr, "Open %s failed: %m\n", opt_out);
		return -1;
	}

	for (n = 0, img = &imgs[0]; n < img_num; img++, n++) {
#ifdef CONFIG_DEBUG_DUMP_IMAGES
		fprintf(stderr, "Pack %s (%s) @ %08x", img->filename,
			str_img_type[img->image_type], img->location);
		if (img->exec_addr)
			fprintf(stderr, ", exec = %x", img->exec_addr);
		fprintf(stderr, "\n");
#endif

		if (load_image(img) < 0) {
			fclose(out_pack);
			remove(opt_out);
			return -1;
		}
		aligned_length += ALIGNED_LENGTH(img->length);
	}

	header.aligned_length = aligned_length;
	header.action_flag = PACK_ACTION;
	header.image_number = img_num;
	header.reserved = (uint32_t)-1;
	fwrite(&header, 1, sizeof(header), out_pack);

	for (n = 0, img = &imgs[0]; n < img_num; img++, n++) {
		struct pack_child_header child;

		child.file_length = (uint32_t)img->length;
		child.image_type = img->image_type;
		child.location = img->location;
		child.reserved = (uint32_t)-1;
		fwrite(&child, 1, sizeof(child), out_pack);

		fwrite(img->binary, 1, img->length, out_pack);
	}

	return 0;
}

#define MMC_IMAGES_INFO_HEADER_WBU		0xAA554257
#define MMC_IMAGES_INFO_HEADER_WBYC		0x63594257

struct mmc_images_info_header {
	uint32_t	magic_WBU;
	uint32_t	n_images;
	uint32_t	reserved;
	uint32_t	magic_WBYC;
};

struct mmc_image_info {
	uint32_t	img_type_number;
	uint32_t	flash_offset;
	uint32_t	exec;
	uint32_t	next_flash_offset;
	uint8_t		image_name[16];
};

static int file_add_mmc_image_info(FILE *fp, struct image *spl)
{
	struct mmc_images_info_header *mmc_images;
	struct mmc_image_info *img_info;
	uint8_t sector[EMMC_SECTOR_SIZE];

	memset(sector, 0xff, sizeof(sector));
	mmc_images = (struct mmc_images_info_header *)sector;
	img_info = (struct mmc_image_info *)(sector + sizeof(*mmc_images));

	mmc_images->magic_WBU = MMC_IMAGES_INFO_HEADER_WBU;
	mmc_images->n_images = 1;
	mmc_images->reserved = 0xffffffff;
	mmc_images->magic_WBYC = MMC_IMAGES_INFO_HEADER_WBYC;

	img_info->img_type_number = ((spl->image_type & 0xffff) << 16) | 0 /* img num */;
	img_info->flash_offset = spl->location;
	img_info->exec = spl->exec_addr;
	img_info->next_flash_offset = spl->location +
		(spl->length + EMMC_SECTOR_SIZE - 1) / EMMC_SECTOR_SIZE - 1;

	/* Warning: If there is no null byte among the first n bytes of src, the
	 * string placed in dest will not be null-terminated.
	 */
	img_info->image_name[sizeof(img_info->image_name) - 1] = '\0';
	strncpy(img_info->image_name, basename(spl->filename),
		sizeof(img_info->image_name) - 1);

	fwrite(sector, 1, sizeof(sector), fp);
	return 0;
}

static int glue_ddr_spl(struct image *imgs, int img_num)
{
	struct image *img_spl = imgs;
	FILE *out;

	if (img_num != 1 || img_spl->image_type != IMAGE_TYPE_SPL) {
		fprintf(stderr, "wrong param for glue ddr and spl\n");
		return -1;
	} else if (load_image(img_spl) < 0) {
		fprintf(stderr, "loading spl failed\n");
		return -1;
	}

	out = fopen(opt_out, "wb+");
	if (!out) {
		fprintf(stderr, "open %s failed\n", opt_out);
		return -1;
	}

	switch (opt_media_type) {
	case MEDIA_TYPE_EMMC:
		/* emmc image info saved in offset 512, size is 512B,
		 * spl saved in 1024
		 */
		file_add_mmc_image_info(out, img_spl);
		break;
	}

	fwrite(img_spl->binary, 1, img_spl->length, out);
	fclose(out);

	return 0;
}

static int translate_images(struct image *imgs, int img_num)
{
	for (int i = 0; i < img_num; i++) {
		struct image *img = &imgs[i];
		int ret = -1;

		if (img->image_type != IMAGE_TYPE_ENV) {
			fprintf(stderr, "Waring: doesn't support translate %s(type: %d)\n",
				img->filename, img->image_type);
			continue;
		}

		switch (img->image_type) {
		case IMAGE_TYPE_ENV:
			ret = translate_image_env(img, opt_out);
			break;
		}

		if (ret < 0)
			return ret;
	}

	return 0;
}

static int parser_images(int argc, char *argv[], struct image **imgs, int *img_num)
{
	struct image *img, *relloc_imgs = *imgs;
	int resize;

	for (int i = 0; i < argc; i++) {
		img = &relloc_imgs[*img_num];
		memset(img, 0, sizeof(*img));

		if (argv[i][0] != '-') {
			fprintf(stderr, "invaild argv: %s\n", argv[i]);
			return -1;
		}

		switch (argv[i][1]) {
		case 'd': /* -ddr, -data */
		case 's': /* -spl */
		case 'e': /* -env */
			if (!argv[i + 1]) {
				fprintf(stderr, "%s need a param\n", argv[i]);
				return -1;
			}

			if (!strcmp(argv[i], "-ddr")) {
				snprintf(opt_ddr, sizeof(opt_ddr), "%s", argv[++i]);
				break;
			} else if (!strcmp(argv[i], "-spl")) {
				img->image_type = IMAGE_TYPE_SPL;
			} else if (!strcmp(argv[i], "-data")) {
				img->image_type = IMAGE_TYPE_DATA;
			} else if (!strcmp(argv[i], "-env")) {
				img->image_type = IMAGE_TYPE_ENV;
			} else {
				fprintf(stderr, "unknown param: %s\n", argv[i]);
				return -1;
			}

			if (parse_image_param(argv[++i], img) == 0) {
				/* prepare memory for the next image */
				++(*img_num);
				resize = sizeof(*img) * (*img_num + 1);

				if (!(relloc_imgs = realloc(relloc_imgs, resize))) {
					fprintf(stderr, "Realloc memory failed.\n");
					return -1;
				}

				*imgs = relloc_imgs;
			} else {
				return -1;
			}
			break;
		default:
			fprintf(stderr, "unknown param: %s\n", argv[i]);
			return -1;
		}
	}

	return 0;
}

static void free_images(struct image *imgs, int img_num)
{
	struct image *img;
	int n;

	for (n = 0, img = &imgs[0]; n < img_num; img++, n++) {
		if (img->binary && img->length > 0)
			free(img->binary);
	}
	free(imgs);
}


static int loading_nupacker_config(const char *cfg, struct image **imgs, int *img_num)
{
	FILE *fp = fopen(cfg, "r");
	int line_number = 1;

	if (!fp) {
		fprintf(stderr, "open %s failed: %m\n", cfg);
		return -1;
	}

	while (1) {
		char *p, line[1024] = { 0 }, *argv[32] = { NULL };
		int len, argc = 0;

		if (!fgets(line, sizeof(line) - 1, fp)) /* EOF */
			break;

		len = strlen(line);
		if (line[len - 1] = '\n') {
			line[len - 1] = '\0';
			len--;
		}

		if (len < 1 || line[0] == '#') /* ignore blank and comments */
			continue;

		argv[argc++] = line;
		while ((p = strchr(line, ' '))) {
			*p = '\0';
			argv[argc++] = ++p;
		}

		if (parser_images(argc, argv, imgs, img_num) < 0) {
			fprintf(stderr, "parser %s: L%d failed: ", cfg, line_number);
			for (int i = 0; i < argc; i++)
				fprintf(stderr, "%s ", argv[i]);
			fprintf(stderr, "\n");
			return -1;
		}

		line_number++;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct image *imgs = malloc(sizeof(*imgs));
	int img_num = 0;
	int ret = -1;

	if (!imgs) {
		fprintf(stderr, "Alloc memory failed: %m\n");
		exit(EXIT_FAILURE);
	} else if (argc <= 1) { /* without any params */
		free(imgs);
		usage();
		exit(EXIT_FAILURE);
	}

	for (int i = 1; i < argc; i++) {
		char opt = argv[i][1];

		/* Print usage messages if a param is n't start with '-',
		 * or this param is '-h'.
		 */
		if (argv[i][0] != '-' || opt == 'h' || opt == '\0') {
			usage();
			goto _exit;
		}

		switch (opt) {
		default:
			fprintf(stderr, "Unknown opt: -%c\n\n", opt);
			usage();
			goto _exit;

		case 'i': /* -i or -ignore-env-crc */
			if (!strcmp(argv[i], "-i")) {
				opt_extract = 0;
				if (argv[++i]) {
					ret = extract_packed_image_file(argv[i]);
					goto _exit;
				}
			} else {
				opt_ignore_env_crc = 1;
			}
			break;

		case 'p':
			opt_pack = 1;
			break;

		case 'E':
			opt_extract_file = argv[++i];
			opt_extract = 1;
			break;
		case 'o':
			opt_out = argv[++i];
			break;

		case 'O':
			opt_out_dir = argv[++i];
			break;

		case 'd': /* -ddr, -data */
		case 's': /* -spl */
		case 'e': /* -env */
			if (!argv[i + 1]) {
				fprintf(stderr, "%s need a param\n", argv[i]);
				goto _exit;
			}

			if (parser_images(2, argv + i, &imgs, &img_num) < 0)
				goto _exit;

			i++;
			break;

		case 'f':
			if (!argv[i + 1]) {
				fprintf(stderr, "%s need a param\n", argv[i]);
				goto _exit;
			}

			if (loading_nupacker_config(argv[++i], &imgs, &img_num) < 0)
				goto _exit;
			break;

		case 'g':
			opt_glue_ddr_spl = 1;
			break;
		case 'm': /* -media=emmc */
			if (!strcmp(&argv[i][7], "nand")) {
				opt_media_type = MEDIA_TYPE_NAND;
			} else if (!strcmp(&argv[i][7], "emmc")) {
				opt_media_type = MEDIA_TYPE_EMMC;
			} else if (!strcmp(&argv[i][7], "spi")) {
				opt_media_type = MEDIA_TYPE_SPI;
			} else {
				fprintf(stderr, "invalid command opt: %s\n", argv[i]);
				goto _exit;
			}
			break;
		}
	}

	if (!opt_pack && !opt_extract) {
		/* try auto translate images */
		if (opt_ddr[0] != '\0') {
			ret = translate_ddr(opt_ddr, opt_out);
		} if (img_num > 0) {
			ret = translate_images(imgs, img_num);
		} else {
			ret = 0;
		}
		goto _exit;
	}

	if (opt_extract) {
		if (opt_extract_file)
			ret = extract_packed_image_file(opt_extract_file);
		else
			fprintf(stderr, "-e need a param!\n");
		goto _exit;
	}

	if (img_num > 0) {
		int need_ddr = 0;

		for (int i = 0; i < img_num; i++) {
			struct image *img = &imgs[i];

			if (img->image_type == IMAGE_TYPE_SPL) {
				need_ddr = 1;
				break;
			} else if (img->location == 0) {
				fprintf(stderr, "image %s doesn't has location attr\n",
					img->filename);
				goto _exit;
			}
		}

		if (!opt_out) {
			fprintf(stderr, "Pack images should add -o param to "
					"to select the target's name.\n");
			goto _exit;
		} else if (need_ddr && !opt_ddr) {
			fprintf(stderr, "-spl need a -ddr configuration\n");
			goto _exit;
		}

		if (opt_glue_ddr_spl)
			ret = glue_ddr_spl(imgs, img_num);
		else
			ret = pack_images(imgs, img_num);

		goto _exit;
	}

_exit:
	free_images(imgs, img_num);
	return ret;
}
