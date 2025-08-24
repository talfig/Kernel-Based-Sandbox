
#include "Policy/LibCallGraph.h"
#include <sstream>

using namespace policy;

void Graph::addNode(const std::string &pretty) {
  Node n;
  n.pretty = pretty;
  nodes.push_back(n);
  adj.emplace_back();
}

size_t Graph::addNodeRetIndex(const std::string &pretty) {
  Node n;
  n.pretty = pretty;
  size_t idx = nodes.size();
  nodes.push_back(n);
  adj.emplace_back();
  return idx;
}

size_t Graph::addEdge(size_t src, size_t dst, const std::string &label) {
  NeighborEdge e{dst, label};
  size_t id = edges.size();
  edges.push_back(e);
  adj[src].push_back(id);
  nodes[src].viewedCalls.push_back(dst);
  return id;
}

std::string Graph::toDOT() const {
  std::ostringstream os;
  os << "digraph \"" << functionName << "\" {\n";
  os << "  rankdir=LR;\n";
  for (size_t i = 0; i < nodes.size(); ++i) {
    const auto &n = nodes[i];
    std::ostringstream label;
    label << "n" << i;
    if (!n.pretty.empty()) label << "\\n" << n.pretty;
    if (n.dummyID >= 0) label << "\\n(dummy=" << n.dummyID << ")";
    if (n.uniqueID >= 0) label << "\\n(uid=" << n.uniqueID << ")";
    os << "  n" << i << " [shape=circle,label=\"" << label.str() << "\"];\n";
  }
  for (size_t src = 0; src < adj.size(); ++src) {
    for (auto eid : adj[src]) {
      const auto &e = edges[eid];
      os << "  n" << src << " -> n" << e.target << " [label=\"" << e.label << "\"];\n";
    }
  }
  os << "}\n";
  return os.str();
}

void Graph::initBuckets(size_t m) {
  mod = m;
  buckets.assign(mod, SIZE_MAX);
  bucketPool.clear();
}

void Graph::insertIntoBuckets(size_t nodeIndex, int dummyID) {
  if (mod == 0) return;
  size_t key = static_cast<size_t>(dummyID % static_cast<int>(mod));
  BucketNode bn{nodeIndex, buckets[key]};
  size_t idx = bucketPool.size();
  bucketPool.push_back(bn);
  buckets[key] = idx;
}

std::string PolicyJSON::serialize() const {
  std::ostringstream os;
  os << "{\n  \"functions\": [\n";
  for (size_t i = 0; i < functions.size(); ++i) {
    const auto &f = functions[i];
    os << "    {\n";
    os << "      \"functionName\": \"" << f.functionName << "\",\n";
    os << "      \"mod\": " << f.mod << ",\n";
    os << "      \"idMode\": \"" << f.idMode << "\",\n";
    os << "      \"callsInOrder\": [\n";
    for (size_t j = 0; j < f.callsInOrder.size(); ++j) {
      const auto &c = f.callsInOrder[j];
      os << "        {\"name\":\"" << c.name << "\",\"uniqueID\":" << c.uniqueID
         << ",\"dummyID\":" << c.dummyID << ",\"resetCount\":" << c.resetCount
         << ",\"irLocation\":\"" << c.irLocation << "\"}";
      if (j + 1 < f.callsInOrder.size()) os << ",";
      os << "\n";
    }
    os << "      ],\n";
    // Graph export
    os << "      \"nodeLabels\": [";
    for (size_t k = 0; k < f.nodeLabels.size(); ++k) {
      os << "\"" << f.nodeLabels[k] << "\"";
      if (k + 1 < f.nodeLabels.size()) os << ",";
    }
    os << "],\n";
    os << "      \"nodeDummyIDs\": [";
    for (size_t k = 0; k < f.nodeDummyIDs.size(); ++k) {
      os << f.nodeDummyIDs[k];
      if (k + 1 < f.nodeDummyIDs.size()) os << ",";
    }
    os << "],\n";
    os << "      \"nodeUniqueIDs\": [";
    for (size_t k = 0; k < f.nodeUniqueIDs.size(); ++k) {
      os << f.nodeUniqueIDs[k];
      if (k + 1 < f.nodeUniqueIDs.size()) os << ",";
    }
    os << "],\n";
    os << "      \"edges\": [\n";
    for (size_t e = 0; e < f.edges.size(); ++e) {
      const auto &E = f.edges[e];
      os << "        {\"src\":" << E.src << ",\"dst\":" << E.dst << ",\"label\":\"" << E.label
         << "\",\"matchDummy\":" << E.matchDummy << ",\"matchUnique\":" << E.matchUnique << "}";
      if (e + 1 < f.edges.size()) os << ",";
      os << "\n";
    }
    os << "      ]\n";
    os << "    }";
    if (i + 1 < functions.size()) os << ",";
    os << "\n";
  }
  os << "  ]\n}\n";
  return os.str();
}
