#ifndef FILTER_MODE_HH
#define FILTER_MODE_HH

// used by client/reporter's infobase element to determine whether we need to send a Report message on invocation of join/leave handlers
enum REPORT_MODE {
	NO_REPORT,
	FILTER_MODE_CHANGE_REPORT,
	SOURCE_LIST_CHANGE_REPORT
};

// used by router/querier's infobase element to determine whether we need to send back a query on reception of a Report record
enum QUERY_MODE {
	NO_QUERY,
	GROUP_QUERY,
	GROUP_AND_SOURCE_QUERY
};

// RFC 3376 page 16-17
enum FilterMode {
    MODE_IS_INCLUDE = 1,
	MODE_IS_EXCLUDE,
	CHANGE_TO_INCLUDE_MODE,
	CHANGE_TO_EXCLUDE_MODE,
    ALLOW_NEW_SOURCES,
    BLOCK_OLD_SOURCES
};

#endif
