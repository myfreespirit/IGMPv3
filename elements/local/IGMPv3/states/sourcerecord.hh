#ifndef SOURCE_RECORD_HH
#define SOURCE_RECORD_HH

// RFC 3376 page 26
class SourceRecord {
public:
	SourceRecord() : _sourceAddress(IPAddress())
	{
	}

	SourceRecord(IPAddress sourceAddress) : _sourceAddress(sourceAddress)
   	{
   	}

	IPAddress _sourceAddress;
	// _sourceTimer
};

#endif
