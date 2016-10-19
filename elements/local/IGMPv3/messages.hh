#ifndef CLICK_MESSAGES_HH
#define CLICK_MESSAGES_HH
#include <click/vector.cc>

struct Query {
	uint8_t type;
	uint8_t max_resp_code;
	uint16_t checksum;
	in_addr group_address;
	unsigned resv:(4);
	unsigned S:(1);
	unsigned QRV:(3);
	uint8_t QQIC;
	uint16_t number_of_sources;
	Vector<in_addr> sources_address;
};


#endif // CLICK_MESSAGES_HH
