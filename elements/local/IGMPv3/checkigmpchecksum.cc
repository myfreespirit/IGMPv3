#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>

#include "messages.hh"
#include "checkigmpchecksum.hh"

CLICK_DECLS

CheckIGMPChecksum::CheckIGMPChecksum()
{
}

CheckIGMPChecksum::~CheckIGMPChecksum()
{
}

int CheckIGMPChecksum::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, 
            "TYPE", cpkP + cpkM, cpUnsigned, &_type,
            "OFFSET", cpkP, cpUnsigned, &_offset, 
            cpEnd) < 0) return -1;

    if (_type != 0x11 && _type != 0x22) {
        errh->error("CheckIGMPChecksum expects a type of value 0x11 or 0x22.");
        return -1;
    }

	return 0;
}

void CheckIGMPChecksum::push(int i, Packet *p)
{
    bool result;
    WritablePacket* q = p->uniqueify();

    if (_type == 0x11) {
        // Query
        Query* igmp = (Query*) (q->data() + _offset);
        result = isValidQueryChecksum(igmp);
    } else if (_type == 0x22) {
        // Report
        Report* igmp = (Report*) (q->data() + _offset);
        result = isValidReportChecksum(igmp);
    }

    if (result) {
        output(0).push(p);
    } else {
        click_chatter("ERROR: CheckIGMPChecksum encountered bad checksum of IGMP, packet dropped.");
        p->kill();
    }
}

bool CheckIGMPChecksum::isValidQueryChecksum(Query* igmp)
{
    unsigned int received = igmp->checksum;

    // Since we do not consider Group-And-Source specific queries, we do not need to worry about the size of source lists
    igmp->checksum = 0;
    unsigned int computed = click_in_cksum((unsigned char*) igmp, sizeof(Query));

    return received == computed;
}

bool CheckIGMPChecksum::isValidReportChecksum(Report* igmp)
{
    unsigned int received = igmp->checksum;

    // Determine the size of the whole packet, including GroupRecords and Addresses
    int groups = ntohs(igmp->number_of_group_records);
    int sources = 0;
    GroupRecord* group = (GroupRecord*)(igmp + 1);
    for (int g = 0; g < groups; g++) {
        int new_sources = ntohs(group->number_of_sources);
        sources += new_sources;

        Addresses* address = (Addresses*)(group + 1);
        group = (GroupRecord*)(address + new_sources);
    }

    igmp->checksum = 0;
    int size = sizeof(Report) + sizeof(GroupRecord)*groups + sizeof(Addresses)*sources;
    unsigned int computed = click_in_cksum((unsigned char*) igmp, size);
    
    return received == computed;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(CheckIGMPChecksum)
