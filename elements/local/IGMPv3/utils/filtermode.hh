#ifndef FILTER_MODE_HH
#define FILTER_MODE_HH

// RFC 3376 page 16
enum FilterMode {
        MODE_IS_INCLUDE = 1,
        MODE_IS_EXCLUDE,
        CHANGE_TO_INCLUDE_MODE,
        CHANGE_TO_EXCLUDE_MODE
};

#endif
