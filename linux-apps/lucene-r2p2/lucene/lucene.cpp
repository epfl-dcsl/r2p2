#include <assert.h>
#include <iostream>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include "LuceneHeaders.h"
#include "MMapDirectory.h"
#include "ParallelMultiSearcher.h"
#include "Sort.h"
#include "SortField.h"
#include "TopFieldDocs.h"
#include "NumericRangeQuery.h"
#include "FieldCache.h"

#include "SearchLucene.h"

using namespace Lucene;
using namespace std;

extern "C" {
	void init_thread() {
		cout << "Initialising Lucene..." << "\n";
		SearchLucene::Instance();
		cout << "Loading index done" << "\n";
	}

	 void search_lucene(char *request, struct iovec *iov) {
		/*Generate the query and do the search.*/
		String query = StringUtils::toUnicode(request);
		TopFieldDocsPtr result = SearchLucene::Instance()->Search(query);

		/*Construct the response.*/
		//TODO could do everything in the stream to avoid copies etc.?
		std::ostringstream oss;
		oss << "totalHits: " << result->totalHits << "\n";
		for (auto p: result->scoreDocs) {
			oss << p->doc <<"\n";
		}
		const std::string tmp = oss.str();
		char* res = new char[tmp.length() + 1];
		std::copy(tmp.c_str(), tmp.c_str() + tmp.length() + 1, res);
		iov->iov_len = tmp.length() + 1;
		if (iov->iov_base)
			delete [] (char *)iov->iov_base;
		iov->iov_base = res;
	}
}
