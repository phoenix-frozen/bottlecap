//call number enum
enum {
	BOTTLE_NULL = 0,
	BOTTLE_INIT,
	BOTTLE_DESTROY,
	BOTTLE_QUERY_FREE_SLOTS,
	BOTTLE_EXPIRE,
	BOTTLE_EXPORT,
	BOTTLE_IMPORT,
	BOTTLE_CAP_ADD,
	BOTTLE_CAP_DELETE,
	BOTTLE_CAP_EXPORT
};

//param type enum
enum {
	BOTTLE_CALL = 0,
	BOTTLE_HEADER,
	BOTTLE_TABLE,
	BOTTLE_SLOTCOUNT,
};
