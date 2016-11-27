#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>

#include "messages.hh"
#include "multicastsender.hh"
#include "infobases/igmprouterstates.hh"

CLICK_DECLS

MulticastSender::MulticastSender()
{
}

MulticastSender::~MulticastSender()
{
}

int MulticastSender::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (cp_va_kparse(conf, this, errh, "ROUTER_STATES", cpkM, cpElementCast, "IGMPRouterStates", &_states, cpEnd) < 0) return -1;
	return 0;
}

void MulticastSender::push(int i, Packet *p)
{
	click_ip* iph = (click_ip*) p->data();

    // click_chatter("Router received a packet from %s on port/interface %d, destined to %s", IPAddress(iph->ip_src).unparse().c_str(), interface, IPAddress(iph->ip_dst).unparse().c_str());

	if (_states->isMulticastAllowed(i, iph->ip_dst, iph->ip_src)) {
		output(i).push(p);
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MulticastSender)
