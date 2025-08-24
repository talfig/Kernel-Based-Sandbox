
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <optional>

namespace policy {

struct NeighborEdge {
  size_t target;        // index of target node
  std::string label;    // libcall name or "epsilon" (ϵ)
};

struct Node {
  size_t nextNode = SIZE_MAX; // optional linear "next" pointer (unused in DOT)
  std::vector<size_t> viewedCalls; // neighbor node indices
  int dummyID = -1; // hashed id
  int uniqueID = -1; // optional unique id (site order) for unique-mode
  std::string pretty; // callee name
};

struct Graph {
  std::string functionName;
  std::vector<Node> nodes;
  std::vector<NeighborEdge> edges;
  std::vector<std::vector<size_t>> adj;

  void addNode(const std::string &pretty = "");
  size_t addNodeRetIndex(const std::string &pretty = "");
  size_t addEdge(size_t src, size_t dst, const std::string &label);
  std::string toDOT() const;

  // Hash table with modulo buckets (bucketed linked lists of node indices)
  struct BucketNode {
    size_t nodeIndex;
    size_t next; // index into bucketPool or SIZE_MAX
  };
  std::vector<size_t> buckets; // head index per bucket into bucketPool
  std::vector<BucketNode> bucketPool;
  size_t mod = 200;

  void initBuckets(size_t m);
  void insertIntoBuckets(size_t nodeIndex, int dummyID);
};

struct PolicyJSON {
  struct LibCallSite {
    std::string name;
    int uniqueID;
    int dummyID;
    int resetCount;
    std::string irLocation;
  };
  struct Edge {
    size_t src;
    size_t dst;
    std::string label; // "ϵ" or callee name
    int matchDummy;    // -1 if not applicable, else dummy id to match
    int matchUnique;   // -1 if not applicable, else unique id to match
  };
  struct FuncPolicy {
    std::string functionName;
    std::vector<LibCallSite> callsInOrder;
    size_t mod = 200;
    std::string idMode; // "unique" or "dummy"
    // Full graph export:
    std::vector<std::string> nodeLabels; // pretty names
    std::vector<int> nodeDummyIDs;
    std::vector<int> nodeUniqueIDs;
    std::vector<Edge> edges; // adjacency
  };

  std::vector<FuncPolicy> functions;

  std::string serialize() const;
};

} // namespace policy
