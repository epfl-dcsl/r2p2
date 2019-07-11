#include <cassert>
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

static String indices[16] = {L"./indices/index0", L"./indices/index1",
L"./indices/index2", L"./indices/index3", L"./indices/index4", L"./indices/index5",
L"./indices/index6", L"./indices/index7", L"./indices/index8", L"./indices/index9",
L"./indices/index10", L"./indices/index11", L"./indices/index12", L"./indices/index13",
L"./indices/index14", L"./indices/index15"};

SortPtr SearchLucene::sortDefault = NULL;
SearcherPtr SearchLucene::searcher = NULL;
QueryParserPtr SearchLucene::parser = NULL;
SearchLucene* SearchLucene::s_instance = NULL;

void SearchLucene::Init() {
	Collection<SearchablePtr> indexSearchers = Collection<SearchablePtr>::newInstance();
	std::vector<IndexReaderPtr> ireaders;
	for (int i = 0; i < NB_INDICES; i++) {
		MMapDirectoryPtr mm = newLucene<MMapDirectory>(indices[i]);
		ireaders.push_back(IndexReader::open(mm, true));
		SearcherPtr index = newLucene<IndexSearcher>(ireaders.back());
		indexSearchers.add(index);
	}

	/* Instantiate the sorter. */
	SearchLucene::sortDefault = newLucene<Sort>(newLucene<SortField>(String(), SortField::SCORE, false));
	String field = L"contents";
	AnalyzerPtr analyzer = newLucene<StandardAnalyzer>(VERSION);
	SearchLucene::parser = newLucene<QueryParser>(VERSION, field, analyzer);
	SearchLucene::searcher = newLucene<ParallelMultiSearcher>(indexSearchers);
}

SearchLucene* SearchLucene::Instance() {
	if (SearchLucene::s_instance == NULL) {
		SearchLucene::s_instance = new SearchLucene;
		SearchLucene::Init();
	}
	assert(SearchLucene::parser != NULL);
	return SearchLucene::s_instance;
}

TopFieldDocsPtr SearchLucene::Search(QueryPtr query) {
	return SearchLucene::searcher->search(query, FilterPtr(), 1000, SearchLucene::sortDefault);
}

TopFieldDocsPtr SearchLucene::Search(String query) {
	QueryPtr q = SearchLucene::parser->parse(query);
	// TODO should I free 'q'?
	return SearchLucene::Search(q);
}
