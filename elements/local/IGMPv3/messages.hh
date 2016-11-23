#ifndef CLICK_MESSAGES_HH
#define CLICK_MESSAGES_HH

#define TYPE_QUERY	0x11
#define TYPE_REPORT	0x22

struct Query {
	uint8_t type;
	uint8_t max_resp_code;
	uint16_t checksum;
	in_addr group_address;
	uint8_t resvSQRV;
//	unsigned resv:(4);
//	unsigned S:(1);
//	unsigned QRV:(3);
	uint8_t QQIC;
	uint16_t number_of_sources;
	//in_addr source_addresses[0];
};

struct SourceAddress{
    in_addr address;
};

struct GroupRecord {
    uint8_t type;
    uint8_t aux_data_len;
    uint16_t number_of_sources;
    in_addr multicast_address;
	//uint32_t aux_data[];
};

struct Report {
    uint8_t type;
    uint8_t reserved_top;
    uint16_t checksum;
    uint16_t reserved_bottom;
	uint16_t number_of_group_records;
};

#endif // CLICK_MESSAGES_HH
