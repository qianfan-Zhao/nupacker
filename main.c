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

#define NUPACKER_VERSION	"1.00"
#define PACK_ALIGN		(64 * 1024)
#define ALIGNED_LENGTH(x)	((((x) + PACK_ALIGN - 1) / PACK_ALIGN) * PACK_ALIGN)

static void usage(void)
{
	fprintf(stderr, "nupacker -i pack.bin: Show packed image's information\n");
	fprintf(stderr, "nupacker -ddr which_dir/ddr.bin\n");
	fprintf(stderr, " -spl which_dir/u-boot-spl.bin@0,exec=0x200\n");
	fprintf(stderr, " [-data which_dir/u-boot.bin@0x100000]\n");
	fprintf(stderr, " [-data which_dir/uImage_dtb.bin@0x200000]\n");
	fprintf(stderr, " [-data which_dir/rootfs.ubi@0x800000]\n");
	fprintf(stderr, " -o which_dir/pack.bin: Pack images\n");
	fprintf(stderr, "nupacker -e which_dir/pack.bin [-O dir]: Extract packed image\n");
	fprintf(stderr, "VERSION: %s\n", NUPACKER_VERSION);
}

/*
 * Global variables used for parser main's command line params.
 */
static const char *opt_extract_file = NULL, *opt_ddr = NULL;
static const char *opt_out_dir = NULL, *opt_out = NULL;
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

static char *load_alloc_file(FILE *fp, long *length)
{
	long l = file_length(fp);
	char *m = NULL;

	if (! (m = malloc(sizeof(char) * l))) {
		fprintf(stderr, "Failed to alloc %ld bytes memory.\n", l);
		return m;
	}

	fread(m, 1, l, fp);
	*length = l;
	return m;
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
	FILE *fp_ddr, *fp_spl;
	char *ddr, *spl;

	if (!(fp_spl = fopen(img->filename, "rb"))) {
		fprintf(stderr, "Open %s failed: %m\n", img->filename);
		return -1;
	}

	if (!(fp_ddr = fopen(opt_ddr, "rb"))) {
		fprintf(stderr, "Open %s failed: %m\n", opt_ddr);
		fclose(fp_spl);
		return -1;
	}

	ddr = load_alloc_file(fp_ddr, &ddr_length);
	spl = load_alloc_file(fp_spl, &spl_length);

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

	fclose(fp_spl);
	fclose(fp_ddr);
	free(spl);
	free(ddr);

	return 0;
}

static int load_image(struct image *img)
{
	FILE *fp = fopen(img->filename, "rb");

	if (!fp) {
		fprintf(stderr, "Open %s failed: %m\n", img->filename);
		return -1;
	}

	switch (img->image_type) {
	case IMAGE_TYPE_SPL:
		load_image_spl(img);
		break;
	default:
		img->binary = load_alloc_file(fp, &img->length);
		break;
	}

	fclose(fp);

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
	FILE *f_packed_image = fopen(packed, "rb");
	long l_packed_image = 0;

	if (!f_packed_image) {
		fprintf(stderr, "Open packed image %s failed: %m\n", packed);
		return -1;
	}

	char *packed_image = load_alloc_file(f_packed_image, &l_packed_image);
	if (!packed_image) {
		fclose(f_packed_image);
		return -1;
	}

	int ret = extract_packed_image(packed_image, l_packed_image);
	fclose(f_packed_image);
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
		}
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

