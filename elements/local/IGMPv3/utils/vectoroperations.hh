#ifndef MY_VECTOROPERATIONS_HH
#define MY_VECTOROPERATIONS_HH

#include <click/vector.hh>
#include <click/ipaddress.hh>
#include <algorithm>

using std::find;

namespace vectoroperations {

	Vector<IPAddress> vector_intersect(Vector<IPAddress> a, Vector<IPAddress> b)
	{
		Vector<IPAddress> result;
		
		for (Vector<IPAddress>::iterator it = a.begin(); it != a.end(); it++) {
			for (Vector<IPAddress>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
				if ((*it) == (*it2)) {
					if (find(result.begin(), result.end(), *it) == result.end()) {
						result.insert(result.end(), *it2);
						break;
					}
				}
			}

		}

		return result;
	}

	Vector<IPAddress> vector_union(Vector<IPAddress> a, Vector<IPAddress> b)
	{
		Vector<IPAddress> result;
		for (Vector<IPAddress>::iterator it = a.begin(); it != a.end(); it++) {
			if (find(result.begin(), result.end(), *it) == result.end()) {
				result.insert(result.end(), *it);
			}
		}

		for (Vector<IPAddress>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
			if (find(result.begin(), result.end(), *it2) == result.end()) {
				result.insert(result.end(), *it2);
			}
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
				if (find(result.begin(), result.end(), *it) == result.end()) {
					result.insert(result.end(), *it);
				}
			}
		}

		return result;
	}


}  // end namespace vectoroperations

#endif
