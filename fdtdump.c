#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* Needed for fdr32_to_cpu and so on. */
#include <libfdt_env.h>

/* Needed for struct and FDT_* macros */
#include <fdt.h>

#include "util.h"

#define ALIGN(x, a)	(((x) + ((a) - 1)) & ~((a) - 1))
#define PALIGN(p, a)	((void *)(ALIGN((unsigned long)(p), (a))))
#define GET_CELL(p)	(p += 4, *((const uint32_t *)(p-4)))

static const char *tagname(uint32_t tag)
{
	static const char * const names[] = {
#define TN(t) [t] = #t
		TN(FDT_BEGIN_NODE),
		TN(FDT_END_NODE),
		TN(FDT_PROP),
		TN(FDT_NOP),
		TN(FDT_END),
#undef TN
	};
	if (tag < ARRAY_SIZE(names))
		if (names[tag])
			return names[tag];
	return "FDT_???";
}

#define dumpf(fmt, args...) \
	do { if (debug) printf("// " fmt, ## args); } while (0)


static void dump_blob(void *blob, bool debug)
{
	uintptr_t blob_off = (uintptr_t)blob;
	struct fdt_header *bph = blob;
	uint32_t off_mem_rsvmap = fdt32_to_cpu(bph->off_mem_rsvmap);
	uint32_t off_dt = fdt32_to_cpu(bph->off_dt_struct);
	uint32_t off_str = fdt32_to_cpu(bph->off_dt_strings);
	struct fdt_reserve_entry *p_rsvmap =
		(struct fdt_reserve_entry *)((char *)blob + off_mem_rsvmap);
	const char *p_struct = (const char *)blob + off_dt;
	/* Get offset to the strings */
	const char *p_strings = (const char *)blob + off_str;
	uint32_t version = fdt32_to_cpu(bph->version);
	uint32_t totalsize = fdt32_to_cpu(bph->totalsize);
	uint32_t tag;
	const char *p, *s, *t;
	int depth, sz, shift;
	int i;
	uint64_t addr, size;

	char *buffer;
	buffer = (char *)malloc(MAX_LEN);

	depth = 0;
	shift = 4;

	uint32_t off_total_size = fdt32_to_cpu(bph->totalsize);

	/* TODO: Remove this additional info. Do I need it? */

	dprintf(buffer, "totalsize: %d\n", off_total_size);

	dprintf(buffer, "// magic:\t\t0x%x\n", fdt32_to_cpu(bph->magic));
	dprintf(buffer, "// totalsize:\t\t0x%x (%d)\n", totalsize, totalsize);
	dprintf(buffer, "// off_dt_struct:\t0x%x\n", off_dt);
	dprintf(buffer, "// off_dt_strings:\t0x%x\n", off_str);
	dprintf(buffer, "// off_mem_rsvmap:\t0x%x\n", off_mem_rsvmap);
	dprintf(buffer, "// version:\t\t%d\n", version);
	dprintf(buffer, "// last_comp_version:\t%d\n",
	       fdt32_to_cpu(bph->last_comp_version));
	if (version >= 2)	
		dprintf(buffer, "// boot_cpuid_phys:\t0x%x\n",
		       fdt32_to_cpu(bph->boot_cpuid_phys));

	if (version >= 3)
		dprintf(buffer, "// size_dt_strings:\t0x%x\n",
		       fdt32_to_cpu(bph->size_dt_strings));
	if (version >= 17)
		dprintf(buffer, "// size_dt_struct:\t0x%x\n",
		       fdt32_to_cpu(bph->size_dt_struct));
	dprintf(buffer, "\n");

	for (i = 0; ; i++) {
		addr = fdt64_to_cpu(p_rsvmap[i].address);
		size = fdt64_to_cpu(p_rsvmap[i].size);
		if (addr == 0 && size == 0)
			break;

		dprintf(buffer, "/memreserve/ %#llx %#llx;\n",
		       (unsigned long long)addr, (unsigned long long)size);
	}

	p = p_struct;
	while ((tag = fdt32_to_cpu(GET_CELL(p))) != FDT_END) {
		dumpf("%04zx: tag: 0x%08x (%s)\n",
		        (uintptr_t)p - blob_off - 4, tag, tagname(tag));

		if (tag == FDT_BEGIN_NODE) {
			s = p;
			p = PALIGN(p + strlen(s) + 1, 4);

			if (*s == '\0')
				s = "/";

			dprintf(buffer, "%*s%s {\n", depth * shift, "", s);

			depth++;
			continue;
		}

		if (tag == FDT_END_NODE) {
			depth--;

			dprintf(buffer, "%*s};\n", depth * shift, "");
			continue;
		}

		if (tag == FDT_NOP) {
			dprintf(buffer, "%*s// [NOP]\n", depth * shift, "");
			continue;
		}

		if (tag != FDT_PROP) {
			fprintf(stderr, "%*s ** Unknown tag 0x%08x\n", depth * shift, "", tag);
			break;
		}
		/* sz - length of the returned values in bytes */
		sz = fdt32_to_cpu(GET_CELL(p));
		/* s - pointer to the property name */
		s = p_strings + fdt32_to_cpu(GET_CELL(p));
		if (version < 16 && sz >= 8)
			p = PALIGN(p, 8);
		t = p;

		p = PALIGN(p + sz, 4);

		dumpf("%04zx: string: %s\n", (uintptr_t)s - blob_off, s);
		dumpf("%04zx: value\n", (uintptr_t)t - blob_off);
		dprintf(buffer, "%*s%s", depth * shift, "", s);
		my_utilfdt_print_data(t, sz, buffer);
		dprintf(buffer, ";\n");
	}
		printf("%s", buffer);
}

int main(int argc, char *argv[])
{
	const char *file;
	char *buf;
	bool debug = false;
	off_t len;

	file = argv[1];

	/* TODO: I will pass the buf a pointer to the device tree blob
	* instead of reading a binary file. */

	buf = utilfdt_read_len(file, &len);
	if (!buf)
		die("could not read: %s\n", file);

	dump_blob(buf, debug);

	return 0;
}
