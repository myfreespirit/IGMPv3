#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>

#include "messages.hh"
#include "multicastreceiver.hh"

CLICK_DECLS

MulticastReceiver::MulticastReceiver()
{
}

MulticastReceiver::~MulticastReceiver()
{
}

int MulticastReceiver::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "CLIENT_STATES", cpkM, cpElementCast, "IGMPClientStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void MulticastReceiver::push(int, Packet *p)
{
	click_ip* iph = (click_ip*) p->data();

	// click_chatter("%s received a packet from %s destined to %s", _states->_source.unparse().c_str(), IPAddress(iph->ip_src).unparse().c_str(), IPAddress(iph->ip_dst).unparse().c_str());

	int interface = 0;
	if (_states->isMulticastAllowed(interface, iph->ip_dst, iph->ip_src)) {
		WritablePacket *clone = p->uniqueify();
		output(interface).push(clone);
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MulticastReceiver)
