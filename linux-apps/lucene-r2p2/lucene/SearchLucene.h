#pragma once

#include <LuceneHeaders.h>
#include "TopFieldDocs.h"
#include <ParallelMultiSearcher.h>

#define NB_INDICES 16

#define VERSION LuceneVersion::LUCENE_30

using namespace Lucene;

class SearchLucene {
public:
	static void Init();
	static SearchLucene* Instance();

	TopFieldDocsPtr Search(QueryPtr query);
	TopFieldDocsPtr Search(String query);

private:
	SearchLucene(){};
	SearchLucene(SearchLucene const&) {};
	SearchLucene& operator=(SearchLucene const&){};

	static SortPtr sortDefault;
	static SearcherPtr searcher;
	static QueryParserPtr parser;
	static SearchLucene* s_instance;
};
