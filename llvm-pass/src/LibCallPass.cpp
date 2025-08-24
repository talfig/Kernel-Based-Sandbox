
#include "Policy/LibCallGraph.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/CFG.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <set>
#include <map>

using namespace llvm;
using namespace policy;

static cl::opt<std::string> DotOutDir(
    "libcall-dot-dir",
    cl::desc("Directory to emit per-function DOT graphs"),
    cl::init("libcall_dot"));

static cl::opt<std::string> PolicyJSONOut(
    "libcall-policy-json",
    cl::desc("Path to emit aggregated policy JSON"),
    cl::init("libcall_policy.json"));

static cl::opt<unsigned> HashMod(
    "libcall-mod",
    cl::desc("Modulo for dummy id hashing"),
    cl::init(200));

static cl::opt<std::string> IdModeOpt(
    "libcall-id-mode",
    cl::desc("ID mode: unique or dummy"),
    cl::init("dummy"));

namespace {

struct LibCallPass : public PassInfoMixin<LibCallPass> {

  static bool isCandidateLibCall(const CallBase &CB) {
    const Function *Callee = CB.getCalledFunction();
    if (!Callee) return false;
    if (!Callee->isDeclaration()) return false;
    StringRef Name = Callee->getName();
    if (Name.startswith("llvm.")) return false;
    return true;
  }

  static Function *getOrInsertDummyDecl(Module &M) {
    LLVMContext &Ctx = M.getContext();
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *IntTy  = Type::getInt32Ty(Ctx);
    auto *FTy = FunctionType::get(VoidTy, {IntTy}, /*isVarArg=*/false);
    FunctionCallee FC = M.getOrInsertFunction("dummy", FTy);
    if (Function *F = dyn_cast<Function>(FC.getCallee())) {
      F->setCallingConv(CallingConv::C);
      return F;
    }
    return nullptr;
  }

  struct BBCallList {
    SmallVector<std::pair<Instruction*, CallBase*>, 4> calls;
    size_t entryNode = SIZE_MAX;
    size_t exitNode  = SIZE_MAX;
  };

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    sys::fs::create_directories(DotOutDir);
    Function *DummyDecl = getOrInsertDummyDecl(M);
    PolicyJSON policyOut;

    std::map<Function*, unsigned> uniqueIdCounterPerFunc;
    std::map<Function*, unsigned> dummyCounterPerFunc;

    for (Function &F : M) {
      if (F.isDeclaration()) continue;

      Graph G;
      G.functionName = std::string(F.getName());
      G.initBuckets(HashMod);

      std::map<const BasicBlock*, BBCallList> bbMap;

      for (BasicBlock &BB : F) {
        BBCallList lst;
        for (Instruction &I : BB) {
          if (auto *CB = dyn_cast<CallBase>(&I)) {
            if (isCandidateLibCall(*CB)) {
              lst.calls.emplace_back(&I, CB);
            }
          }
        }
        bbMap[&BB] = std::move(lst);
      }

      std::map<Instruction*, size_t> callNodeIndex;
      for (auto &kv : bbMap) {
        auto &lst = kv.second;
        for (auto &pr : lst.calls) {
          CallBase *CB = pr.second;
          std::string pretty = CB->getCalledFunction()->getName().str();
          size_t idx = G.addNodeRetIndex(pretty);
          callNodeIndex[pr.first] = idx;
        }
      }

      for (auto &kv : bbMap) {
        const BasicBlock *BB = kv.first;
        auto &lst = kv.second;
        if (!lst.calls.empty()) {
          lst.entryNode = callNodeIndex[lst.calls.front().first];
          lst.exitNode  = callNodeIndex[lst.calls.back().first];
        }
        for (size_t i = 0; i + 1 < lst.calls.size(); ++i) {
          auto *CB1 = lst.calls[i].second;
          auto *CB2 = lst.calls[i+1].second;
          size_t n1 = callNodeIndex[lst.calls[i].first];
          size_t n2 = callNodeIndex[lst.calls[i+1].first];
          std::string label = CB1->getCalledFunction()->getName().str();
          G.addEdge(n1, n2, label);
        }
        if (!lst.calls.empty()) {
          for (const BasicBlock *Succ : successors(BB)) {
            auto it = bbMap.find(Succ);
            if (it != bbMap.end() && !it->second.calls.empty()) {
              size_t src = lst.exitNode;
              size_t dst = it->second.entryNode;
              G.addEdge(src, dst, "ϵ");
            }
          }
        }
      }

      PolicyJSON::FuncPolicy funcPol;
      funcPol.functionName = G.functionName;
      funcPol.mod = HashMod;
      funcPol.idMode = IdModeOpt;

      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          auto *CB = dyn_cast<CallBase>(&I);
          if (!CB || !isCandidateLibCall(*CB)) continue;

          unsigned uniqueID = ++uniqueIdCounterPerFunc[&F];
          unsigned &dc = dummyCounterPerFunc[&F];
          unsigned reset = dc / HashMod;
          unsigned dummyID = dc % HashMod;
          ++dc;

          auto itNode = callNodeIndex.find(&I);
          if (itNode != callNodeIndex.end()) {
            auto idx = itNode->second;
            G.nodes[idx].dummyID = static_cast<int>(dummyID);
            G.nodes[idx].uniqueID = static_cast<int>(uniqueID);
            G.insertIntoBuckets(idx, dummyID);
          }

          IRBuilder<> B(&I);
          Value *Arg = nullptr;
          if (IdModeOpt == "unique") {
            Arg = B.getInt32(uniqueID);
          } else {
            Arg = B.getInt32(dummyID);
          }
          B.CreateCall(DummyDecl, {Arg});

          std::string loc = "unknown";
          if (I.getDebugLoc()) {
            auto DL = I.getDebugLoc();
            loc = (Twine("line ") + Twine(DL.getLine())).str();
          }
          PolicyJSON::LibCallSite site;
          site.name = CB->getCalledFunction()->getName().str();
          site.uniqueID = (IdModeOpt == "unique") ? (int)uniqueID : -1;
          site.dummyID = (int)dummyID;
          site.resetCount = (int)reset;
          site.irLocation = loc;
          funcPol.callsInOrder.push_back(site);
        }
      }

      // Export full graph structure into JSON for enforcement
      for (const auto &n : G.nodes) {
        funcPol.nodeLabels.push_back(n.pretty);
        funcPol.nodeDummyIDs.push_back(n.dummyID);
        funcPol.nodeUniqueIDs.push_back(n.uniqueID);
      }
      for (size_t src = 0; src < G.adj.size(); ++src) {
        for (auto eid : G.adj[src]) {
          const auto &E = G.edges[eid];
          PolicyJSON::Edge je;
          je.src = src;
          je.dst = E.target;
          je.label = E.label;
          // If label is epsilon, matching is not applicable
          if (E.label == "ϵ") {
            je.matchDummy = -1;
            je.matchUnique = -1;
          } else {
            // Find the matching node at src to determine its id for label matching.
            // We use the node at 'src' as the emitter: label == callee of 'src'.
            je.matchDummy = G.nodes[src].dummyID;
            je.matchUnique = G.nodes[src].uniqueID;
          }
          funcPol.edges.push_back(je);
        }
      }

      // Emit DOT
      {
        std::error_code EC;
        std::string path = (DotOutDir + "/" + std::string(F.getName()) + ".dot");
        raw_fd_ostream OS(path, EC, sys::fs::OF_Text);
        if (EC) {
          errs() << "Error opening DOT file: " << path << " : " << EC.message() << "\n";
        } else {
          OS << G.toDOT();
        }
      }

      // Record function policy
      policyOut.functions.push_back(std::move(funcPol));
    }

    // Emit policy JSON
    {
      std::error_code EC;
      raw_fd_ostream OS(PolicyJSONOut, EC, sys::fs::OF_Text);
      if (EC) {
        errs() << "Error opening policy JSON file: " << PolicyJSONOut << " : " << EC.message() << "\n";
      } else {
        OS << policyOut.serialize();
      }
    }

    return PreservedAnalyses::none();
  }
};

} // end anonymous namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "LibCallPass", "1.1",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
          [](StringRef Name, ModulePassManager &MPM,
             ArrayRef<PassBuilder::PipelineElement>) {
            if (Name == "libcall") {
              MPM.addPass(LibCallPass());
              return true;
            }
            return false;
          });
    }
  };
}
