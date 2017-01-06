#ifndef CLICK_CHECKIGMPCHECKSUM_HH
#define CLICK_CHECKIGMPCHECKSUM_HH

#include <click/element.hh>
#include "messages.hh"

CLICK_DECLS

/* Verifies the checksum field is correctly computed.
 * Packets with wrong checksum are killed.
 */
class CheckIGMPChecksum : public Element {
	public:
		CheckIGMPChecksum();
		~CheckIGMPChecksum();
		
		const char *class_name() const	{ return "CheckIGMPChecksum"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);

    private:
        bool isValidQueryChecksum(Query* igmp);
        bool isValidReportChecksum(Report* igmp);

        unsigned int _type;
        unsigned int _offset;
};

CLICK_ENDDECLS

#endif
