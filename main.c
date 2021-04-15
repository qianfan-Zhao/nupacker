/*
 * nupacker: A tool for packing all images to nuwriter format.
 *
 * Copyright (C) qianfan Zhao <qianfanguijin@163.com>
 * License under GPL.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NUPACKER_VERSION	"1.02"
#define PACK_ALIGN		(64 * 1024)
#define ALIGN(s, a)		(((s) + (a) - 1) / (a) * (a))
#define ALIGNED_LENGTH(x)	ALIGN(x, PACK_ALIGN)

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

static void usage(void)
{
	fprintf(stderr, "nupacker -i pack.bin: Show packed image's information\n");
	fprintf(stderr, "nupacker -ddr which_dir/ddr.ini\n");
	fprintf(stderr, "         -spl which_dir/u-boot-spl.bin@0,exec=0x200\n");
	fprintf(stderr, "         [-data which_dir/u-boot.bin@0x100000]\n");
	fprintf(stderr, "         [-data which_dir/uImage_dtb.bin@0x200000]\n");
	fprintf(stderr, "         [-data which_dir/rootfs.ubi@0x800000]\n");
	fprintf(stderr, "         -o which_dir/pack.bin: Pack images\n");
	fprintf(stderr, "nupacker -e which_dir/pack.bin [-O dir]: Extract packed image\n");
	fprintf(stderr, "nupacket -t ddr.ini [-o ddr.bin]:\n");
	fprintf(stderr, "nupacket -t ddr.bin [-o ddr.ini]:\n");
	fprintf(stderr, "  Translate ddr configuration between ini and bin\n");
	fprintf(stderr, "  Write translated data to stdout default\n");
	fprintf(stderr, "nupacker -g -ddr which_dir/ddr.ini\n");
	fprintf(stderr, "            -spl which_dir/u-boot-spl.bin@0,exec=0x200\n");
	fprintf(stderr, "            -o which_dir/u-boot-spl-ddr.bin: Glue ddr and uboot\n");
	fprintf(stderr, "VERSION: %s\n", NUPACKER_VERSION);
}

/*
 * Global variables used for parser main's command line params.
 */
static const char *opt_extract_file = NULL, *opt_ddr = NULL;
static const char *opt_out_dir = NULL, *opt_out = NULL;
static const char *opt_ddr_translate = NULL;
static int opt_glue_ddr_spl = 0;
static int opt_extract = 0;
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

static int translate_ddr_bin2ini(const char *f_bin, const char *f_ini)
{
	FILE *fp_ini = !f_ini ? stdout : fopen(f_ini, "w+");
	int i = 0, items = 0, ret = -1;
	long length = 0;
	char *p, *bin;

	if (!fp_ini) {
		fprintf(stderr, "Open/Create %s failed: %m", f_ini);
		return ret;
	}

	if (!(bin = load_alloc_file(f_bin, "rb", &length)))
		goto _close;

	uint32_t header = u32_little_endian(bin[0], bin[1], bin[2], bin[3]);
	if (header != ddr_bin_header) {
		fprintf(stderr, "Invalid header: %X\n", header);
		goto _free;
	}

	items = u32_little_endian(bin[4], bin[5], bin[6], bin[7]);
	long l = items * 8 + sizeof(ddr_bin_header) + 4;
	if (l > length) {
		fprintf(stderr, "Length too larger: %X%X%X%X\n", bin[4],
				bin[5], bin[6], bin[7]);
		goto _free;
	}

	for (i = 0, p = bin + 8; i < items; i++, p += 8) {
		unsigned int addr = u32_little_endian(p[0], p[1], p[2], p[3]);
		unsigned int val  = u32_little_endian(p[4], p[5], p[6], p[7]);

		fprintf(fp_ini, "0x%08X=0x%08X\n", addr, val);
	}
	ret = 0;

_free:
	free(bin);
_close:
	if (f_ini)
		fclose(fp_ini);

	return ret;
}

static int translate_ddr(const char *in, const char *out)
{
	const char *suffix = &in[strlen(in) - strlen(".bin")];

	if (strlen(in) > strlen("1.bin")) {
		if (!strncmp(suffix, ".bin", 4))
			return translate_ddr_bin2ini(in, out);
		else if (!strncmp(suffix, ".ini", 4))
			return translate_ddr_ini2bin(in, out);
	}

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
};

static int parse_image_param(const char *param, struct image *img)
{
	char *at, *exec, *endp = NULL;
	uint32_t location, exec_addr;

	/* which_dir/u-boot-spl.bin@0,exec=0x200 or
	 * which_dir/u-boot.bin@0x100000
	 */
	if (!(at = strstr(param, "@"))) {
		fprintf(stderr, "Please input the image's location\n");
		return -1;
	}

	location = (uint32_t)strtoul(at + 1, &endp, 16);
	if (*endp != '\0' && *endp != ',') {
		fprintf(stderr, "Parse location failed: %s\n", param);
		return -1;
	}

	if ((exec = strstr(param, "exec="))) {
		exec_addr = (uint32_t)strtoul(exec + 5, &endp, 16);
		if (!endp != '\0') {
			fprintf(stderr, "Parse exec failed: %s\n", param);
			return -1;
		}
		img->exec_addr = exec_addr;
	}

	for (int i = 0; i < at - param; i++)
		img->filename[i] = param[i];
	img->location = location;

	return 0;
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

#define SPL_HEADER_MAGIC				0x4e565420

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

static int load_image(struct image *img)
{
	img->binary = NULL;
	img->length = 0;

	switch (img->image_type) {
	case IMAGE_TYPE_SPL:
		load_image_spl(img);
		break;
	default:
		img->binary = load_alloc_file(img->filename, "rb",
					      &img->length);
		break;
	}

	return (img->binary && img->length > 0) ? 0 : -1;
}

/*
 * Save the unextraced spl into file.
 */
static int save_child_spl(struct pack_spl_header *spl, int ddr_length,
			  int spl_length)
{
	const char *data = (const char *)(spl + 1);
	char save_file[128];

	if (opt_extract) {
		const char *file[2] = {"ddr.bin",  "0x0.bin"};
		const int length[2] = {ddr_length, spl_length};

		for (int i = 0; i < 2; i++) {
			snprintf(save_file, sizeof(save_file), "%s/%s",
				 OUT_DIR, file[i]);

			FILE *fp = fopen(save_file, "wb+");
			if (!fp) {
				fprintf(stderr, "Open %s failed: %m\n", save_file);
				return -1;
			}
			fwrite(data, 1, length[i], fp);
			fclose(fp);

			data += length[i];
		}
	}

	return 0;
}

static int save_child(struct pack_child_header *child)
{
	const char *data = (const char *)(child + 1);
	char save_file[128];

	if (opt_extract) {
		snprintf(save_file, sizeof(save_file), "%s/0x%x.bin",
			 OUT_DIR, child->location);

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
		printf("Found %s @ 0x%08x, exec = 0x%08x, size = %d\n",
			str_img_type[child->image_type],
			child->location, spl->exe_addr, spl_length);

		if (save_child_spl(spl, ddr_length, spl_length) < 0)
			return -1;
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

	/* glue ddr and spl doesn't need pack spl header, skip it */
	fwrite(img_spl->binary + sizeof(struct pack_spl_header),
		1,
		img_spl->length - sizeof(struct pack_spl_header),
		out);
	fclose(out);

	return 0;
}

int main(int argc, char *argv[])
{
	struct image *imgs = malloc(sizeof(*imgs));
	struct image *new_img, *img = imgs;
	int n, img_num = 0, need_ddr = 0;
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

		case 'i':
			opt_extract = 0;
			if (argv[++i]) {
				ret = extract_packed_image_file(argv[i]);
				goto _exit;
			}
			break;

		case 'e':
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
			if (!argv[i + 1]) {
				fprintf(stderr, "%s need a param\n", argv[i]);
				goto _exit;
			}

			memset(img, 0, sizeof(*img));

			if (!strcmp(argv[i], "-ddr")) {
				opt_ddr = argv[++i];
				break;
			} else if (!strcmp(argv[i], "-spl")) {
				/* SPL is glue u-boot-spl.bin and ddr */
				img->image_type = IMAGE_TYPE_SPL;
				need_ddr = 1;
			} else if (!strcmp(argv[i], "-data")) {
				img->image_type = IMAGE_TYPE_DATA;
			} else {
				fprintf(stderr, "Unknow param: %s\n\n", argv[i]);
				goto _exit;
			}

			if (parse_image_param(argv[++i], img) < 0)
				goto _exit;

			++img_num;
			/* Prepare memory for next image */
			int resize = sizeof(*img) * (img_num + 1);
			if (!(new_img = realloc(imgs, resize))) {
				fprintf(stderr, "Realloc memory failed.\n");
				goto _exit;
			}
			imgs = new_img;
			img = &imgs[img_num];

			break;

		case 't':
			if (!argv[i + 1]) {
				fprintf(stderr, "%s need a param\n", argv[i]);
				goto _exit;
			}
			opt_ddr_translate = argv[++i];
			break;
		case 'g':
			opt_glue_ddr_spl = 1;
			break;
		}
	}

	if (opt_ddr_translate) {
		ret = translate_ddr(opt_ddr_translate, opt_out);
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
	for (n = 0, img = &imgs[0]; n < img_num; img++, n++) {
		if (img->binary && img->length > 0)
			free(img->binary);
	}
	free(imgs);

	return ret;
}

