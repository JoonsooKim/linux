get_page_owner_data()
{
	if [ "$FILE" == "" ]; then
		cat /sys/kernel/debug/page_owner
	else
		cat $FILE
	fi | \
	grep PFN -B 1 -A 1 | grep ^-- -v
}

parse_page_owner()
{
get_page_owner_data | awk ' BEGIN {
		prev_pfn = 0;
	}

	function print_pfn_type(pfn, type)
	{
		print pfn " " type;
	}

	{
		match($0, /mask 0x[0-9a-f]+/);
		gfp = substr($0, RSTART+5, RLENGTH-5);
		if (RSTART) {
			gfp_num = strtonum(gfp);
			movable_bit = !!and(gfp_num, 0x8);
			reclaim_bit = !!and(gfp_num, 0x80000);
			if (movable_bit)
				type = "movable";
			else
				type = "unmovable";
		
			match($0, /order [0-9]+/);
			order = strtonum(substr($0, RSTART+6, RLENGTH-6));

			next;
		}
		
		match($0, /PFN [0-9]+/);
		if (RSTART) {
			pfn = strtonum(substr($0, RSTART+4, RLENGTH-4));
			match($0, /type [0-9]+/);
			mt = strtonum(substr($0, RSTART+5, RLENGTH-5));
			next;
		}

		# check anonymous pages
		if (match($0, /do_wp_page/) || match($0, /read_swap_cache_async/) || \
			match($0, /handle_pte_fault/)) {
			type = "anon";
		}

		# check CMA pages
		if (mt == 4)
			type = "cma";

		for (i = prev_pfn + 1; i < pfn; i++) {
			if (type == "cma")
				print_pfn_type(i, type);
			else
				print_pfn_type(i, "free");
		}

		pages = lshift(1, order);
		for (i = pfn; i < pfn + pages; i++)
			print_pfn_type(i, type);

		prev_pfn = i - 1;
	}'
}

get_page_types_data()
{
	if [ "$FILE" == "" ]; then
		./page-types -L -N
	else
		cat $FILE
	fi | \
	grep -v offset
}

parse_page_types()
{
get_page_types_data | awk -v max_order="$MAX_ORDER" ' 
	function print_pfn_type(pfn, type)
	{
		print pfn " " type;
	}

	{
		if (!skip_typed_pfn)
			typed_pfn = pfn;
		pfn = strtonum("0x" $1);
		skip_typed_pfn = false;

		# LRU pages (FILE, ANON)
		match($2, /l/);
		if (RSTART) {
			match ($2, /a/);
			if (RSTART)
				type = "anon";
			else
				type = "movable";

			print_pfn_type(pfn, type);
			next;
		}

		match($2, /B/);
		if (RSTART) {
			type = "free";
			print_pfn_type(pfn, type);
			next;
		}

		match($2, /n/);
		if (RSTART) {
			type = "hole";
			print_pfn_type(pfn, type);
			next;
		}

		# Regard non-flagged page as ordered page with previous type
		match($2, /______________________________________/);
		if (RSTART) {
			skip_typed_pfn = true;
			if (rshift(typed_pfn, max_order) == rshift(pfn, max_order))
				print_pfn_type(pfn, type);
			else
				print_pfn_type(pfn, "unknown");

			next;
		}

		type = "unmovable";
		print_pfn_type(pfn, type);

	}'
}

get_raw()
{
	if [ "$RAW" == "" ]; then
		return;
	fi

	$CMD;
}

get_bitmap()
{
	if [ "$BITMAP" == "" ]; then
		return;
	fi

	$CMD | awk -v pageblock_order="$PAGEBLOCK_ORDER" -v max_order="$MAX_ORDER" \
		-v hole_order="$HOLE_ESTIMATE_ORDER" \
	' BEGIN { pageblock_nr = lshift(1, pageblock_order);
		line_max = strtonum(128);
		max_order_nr = lshift(1, max_order); }

	function symbol(type)
	{
		if (type == "unmovable")
			return "0";
		else if (type == "movable")
			return "-";
		else if (type == "anon")
			return "-";
		else if (type == "cma")
			return "C";
		else if (type == "free")
			return " ";
		else if (type == "hole")
			return "X";
		else
			return "X";
	}

	function is_hole()
	{
		if (!hole_order)
			return false;

		count = strtonum(0);
		order_nr = lshift(1, strtonum(hole_order));
				
		while (count < max_order_nr) {
			hole = "yes";
			for (i = 0; i < order_nr; i++) {
				type = arr[count + strtonum(i)];
				if (type != "free") {
					hole = "no";
					break;
				}
			}

			if (hole == "yes")
				next;

			count += order_nr;
		}

		if (hole == "yes")
			return true;

		return false;
	}

	{
		pfn = strtonum($1);
		arr[pfn % max_order_nr] = $2;

		if (pfn % max_order_nr != max_order_nr - 1)
			next;

		if (is_hole())
			next;

		for (i = 0; i < max_order_nr; i++) {
			printf("%s", symbol(arr[i]));
			if (i % line_max == line_max - 1)
				printf("\n");
			if (i % pageblock_nr == pageblock_nr - 1)
				printf("\n");
		}
		printf("\n");
	}'
}

get_summary()
{
	if [ "$SUMMARY" == "" ]; then
		return;
	fi

	$CMD | awk -v hole_order="$HOLE_ESTIMATE_ORDER" -v max_order="$MAX_ORDER" \
	' BEGIN { max_order_nr = lshift(1, max_order); }

	function is_hole()
	{
		if (!hole_order)
			return false;

		count = strtonum(0);
		order_nr = lshift(1, strtonum(hole_order));
				
		while (count < max_order_nr) {
			hole = "yes";
			for (i = 0; i < order_nr; i++) {
				type = arr[count + strtonum(i)];
				if (type != "free") {
					hole = "no";
					break;
				}
			}

			if (hole == "yes")
				next;

			count += order_nr;
		}

		if (hole == "yes")
			return true;

		return false;
	}

	{
		pfn = strtonum($1);
		arr[pfn % max_order_nr] = $2;

		if (pfn % max_order_nr != max_order_nr - 1)
			next;

		if (is_hole())
			next;

		for (i = 0; i < max_order + 1; i++) {
			count = strtonum(0);
			order_nr = lshift(1, strtonum(i));
			while (count < max_order_nr) {
				buddy = "yes";
				reclaim = "yes";
				compaction = "yes";
				for (j = 0; j < order_nr; j++) {
					type = arr[count + strtonum(j)];
					if (type != "free") {
						buddy = "no";
						if (type != "movable") {
							reclaim = "no";
							if (type != "anon") {
								compaction = "no";

								# We can bail out when we confirm that
								# compaction cannot be possible
								break;
							}
						}
					}
				}

				count += order_nr;
				if (buddy == "yes")
					ordered_pages_buddy[i]++;
				if (reclaim == "yes")
					ordered_pages_reclaim[i]++;
				if (compaction == "yes")
					ordered_pages_compaction[i]++;
			}
		}
	}
	
	END {
		printf("%12s:\t", "Order");
		for (i = 0; i < max_order + 1; i++) {
			printf("%d\t", i);
		}
		printf("\n");

		printf("%12s:\t", "Buddy");
		for (i = 0; i < max_order + 1; i++) {
			printf("%d\t", ordered_pages_buddy[i]);
		}
		printf("\n");

		printf("%12s:\t", "Swap");
		for (i = 0; i < max_order + 1; i++) {
			printf("%d\t", ordered_pages_reclaim[i]);
		}
		printf("\n");

		printf("%12s:\t", "Compaction");
		for (i = 0; i < max_order + 1; i++) {
			printf("%d\t", ordered_pages_compaction[i]);
		}
		printf("\n");
	}'
}

usage()
{
	echo "Invalid usage: $SCRIPT_NAME -t [page_types|page_owner] -f [filename] -H hole_order [-b] [-s] [-r]";
}

set_cmd()
{
	if [ "$1" == "page_types" ]; then
		CMD="parse_page_types";
	elif [ "$1" == "page_owner" ]; then
		CMD="parse_page_owner";
	fi
}

HOLE_ESTIMATE_ORDER=0
PAGEBLOCK_NR=512
PAGEBLOCK_ORDER=9
MAX_ORDER=10
SCRIPT_NAME=`basename $0`

ARGS=`getopt -o f:t:H:bsr -- "$@"`
while true; do
	case "$1" in
		-f) FILE=$2; shift 2;;
		-t) TYPE=$2; set_cmd $TYPE; shift 2;;
		-H) HOLE_ESTIMATE_ORDER=$2; shift 2;;
		-b) BITMAP=1; shift 1;;
		-s) SUMMARY=1; shift 1;;
		-r) RAW=1; shift 1;;
		*) shift 1; break;;
	esac
done

if [ "$CMD" == "" ]; then
	usage;
	exit;
fi

get_raw;
get_bitmap;
get_summary;
