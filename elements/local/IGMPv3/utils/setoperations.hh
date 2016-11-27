#ifndef MY_SETOPERATIONS_HH
#define MY_SETOPERATIONS_HH

#include <set>

using std::set;

namespace setoperations {

	set<String> set_intersect(set<String> a, set<String> b)
	{
		set<String> result;
		for (set<String>::iterator it = a.begin(); it != a.end(); it++) {
			for (set<String>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
				if ((*it) == (*it2)) {
					result.insert(result.end(),*it2);
					break;
				}
			}

		}

		return result;
	}

	set<String> set_union(set<String> a, set<String> b)
	{
		set<String> result;
		for (set<String>::iterator it = a.begin(); it != a.end(); it++) {
			result.insert(result.end(),*it);
		}

		for (set<String>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
			result.insert(result.end(),*it2);
		}

		return result;
	}

	set<String> set_difference(set<String> a, set<String> b)
	{
		set<String> result;
		for (set<String>::iterator it = a.begin(); it != a.end(); it++) {
			bool foundMatch = false;
			for (set<String>::iterator it2 = b.begin(); it2 != b.end(); it2++) {
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

}  // namespace setoperations

#endif
