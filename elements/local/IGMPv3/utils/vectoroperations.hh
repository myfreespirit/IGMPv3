#ifndef MY_VECTOROPERATIONS_HH
#define MY_VECTOROPERATIONS_HH

#include <click/vector.hh>
#include <click/ipaddress.hh>

namespace vectoroperations {

	Vector<IPAddress> vector_intersect(Vector<IPAddress> a, Vector<IPAddress> b)
	{
		Vector<IPAddress> result;
		
		for (Vector<IPAddress>::iterator it = a.begin(); it != a.end(); it++) {
			for (Vector<IPAddress>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
				if ((*it) == (*it2)) {
					result.insert(result.end(),*it2);
				}
			}

		}

		return result;
	}


	Vector<IPAddress> vector_union(Vector<IPAddress> a, Vector<IPAddress> b)
	{
		Vector<IPAddress> result;
		for (Vector<IPAddress>::iterator it = a.begin(); it != a.end(); it++) {
			result.insert(result.end(),*it);
		}

		for (Vector<IPAddress>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
			result.insert(result.end(),*it2);
		}

		return result;

	}

	Vector<IPAddress> vector_difference(Vector<IPAddress> a, Vector<IPAddress> b)
	{
		Vector<IPAddress> result;
		for (Vector<IPAddress>::iterator it = a.begin(); it != a.end(); it++) {
			bool foundMatch = false;
			for (Vector<IPAddress>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
				if ((*it) == (*it2)) {
					foundMatch = true;
					break;
				}
		
			}
			if (!foundMatch) {
				result.insert(result.end(), *it);
			}
		}

		return result;
	}


}  //end namespace

#endif
