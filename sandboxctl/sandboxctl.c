
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#define DEVICE_PATH "/dev/libcallsandbox"
#define IOCTL_MAGIC 'L'
#define IOCTL_LOAD_POLICY _IOW(IOCTL_MAGIC, 0x01, void*)

struct edge {
  uint32_t src;
  uint32_t dst;
  int32_t  match_id;
  uint8_t  is_epsilon;
} __attribute__((packed));

struct policy_blob {
  uint32_t pid;
  uint32_t num_nodes;
  uint32_t num_edges;
  uint32_t id_mode; // 0=dummy 1=unique
};

// Very small JSON extractor (expects the JSON emitted by the LLVM pass)
static char* slurp(const char* path, size_t *len_out) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buf = (char*)malloc(n+1);
  if (!buf) { fclose(f); return NULL; }
  if (fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
  buf[n] = 0;
  fclose(f);
  if (len_out) *len_out = (size_t)n;
  return buf;
}

static int find_value(const char *json, const char *key, char *out, size_t outsz) {
  const char *p = strstr(json, key);
  if (!p) return -1;
  p = strchr(p, ':');
  if (!p) return -1;
  p++;
  while (isspace((unsigned char)*p)) p++;
  const char *q = p;
  int in_string = (*q == '"');
  if (in_string) { q++; p = q; while (*q && *q != '"') q++; }
  else { while (*q && *q != ',' && *q != ']' && *q != '}') q++; }
  size_t n = (size_t)(q - p);
  if (n >= outsz) n = outsz - 1;
  memcpy(out, p, n);
  out[n] = 0;
  return 0;
}

// Parse one function's graph from JSON into edges (matching by id mode)
static int extract_graph_edges(const char *json, int func_index,
                               int id_mode, uint32_t **edges_out, uint32_t *num_edges_out,
                               uint32_t *num_nodes_out)
{
  // Find the Nth occurrence of "\"edges\": [" and then scan entries
  const char *p = json;
  for (int i = 0; i <= func_index; ++i) {
    p = strstr(p, "\"edges\":");
    if (!p) return -1;
    p += 8;
  }
  const char *start = strchr(p, '[');
  const char *end = strchr(start, ']');
  if (!start || !end || end <= start) return -1;

  // Also get node counts by scanning "nodeLabels"
  const char *nl = strstr(p, "\"nodeLabels\":");
  if (!nl) return -1;
  const char *nlb = strchr(nl, '[');
  const char *nle = strchr(nlb, ']');
  if (!nlb || !nle) return -1;

  // Count nodes
  uint32_t nodes = 0;
  for (const char *t = nlb; t < nle; ++t) if (*t == ',') nodes++;
  // nodes = commas + 1 if non-empty
  if (nle - nlb > 2) nodes = nodes + 1; else nodes = 0;
  *num_nodes_out = nodes;

  // Count edges by commas/braces
  uint32_t edges_count = 0;
  for (const char *t = start; t < end; ++t) if (*t == '{') edges_count++;
  struct edge *edges = (struct edge*)calloc(edges_count, sizeof(struct edge));
  if (!edges) return -1;

  // Crude parse loop
  uint32_t idx = 0;
  const char *cur = start;
  while (cur && cur < end) {
    const char *es = strchr(cur, '{');
    if (!es || es >= end) break;
    const char *ee = strchr(es, '}');
    if (!ee) break;
    char buf[64];
    // src
    strncpy(buf, "", sizeof(buf));
    const char *field = strstr(es, "\"src\"");
    if (field && field < ee && find_value(field, "src", buf, sizeof(buf)) == 0) {
      edges[idx].src = (uint32_t)atoi(buf);
    }
    // dst
    strncpy(buf, "", sizeof(buf));
    field = strstr(es, "\"dst\"");
    if (field && field < ee && find_value(field, "dst", buf, sizeof(buf)) == 0) {
      edges[idx].dst = (uint32_t)atoi(buf);
    }
    // label
    strncpy(buf, "", sizeof(buf));
    field = strstr(es, "\"label\"");
    if (field && field < ee && find_value(field, "label", buf, sizeof(buf)) == 0) {
      if (strcmp(buf, "\"ϵ\"") == 0 || strcmp(buf, "ϵ") == 0) {
        edges[idx].is_epsilon = 1;
      }
    }
    // match ids
    strncpy(buf, "", sizeof(buf));
    if (id_mode == 0) { // dummy
      field = strstr(es, "\"matchDummy\"");
    } else {
      field = strstr(es, "\"matchUnique\"");
    }
    if (field && field < ee && find_value(field, (id_mode==0)?"matchDummy":"matchUnique", buf, sizeof(buf)) == 0) {
      edges[idx].match_id = atoi(buf);
    } else {
      edges[idx].match_id = -1;
    }
    idx++;
    cur = ee + 1;
  }

  *edges_out = (uint32_t*)edges;
  *num_edges_out = edges_count;
  return 0;
}

static void usage(const char *argv0) {
  fprintf(stderr, "Usage: %s -p <pid> -j <policy.json> [-f <function-index>] [--unique]\n", argv0);
  fprintf(stderr, "Loads the function's automaton into the kernel sandbox for the given PID.\n");
}

int main(int argc, char **argv)
{
  int opt;
  pid_t pid = -1;
  const char *json_path = NULL;
  int func_index = 0;
  int id_mode = 0; // 0=dummy, 1=unique

  for (int i=1; i<argc; ++i) {
    if (!strcmp(argv[i], "-p") && i+1<argc) { pid = (pid_t)atoi(argv[++i]); }
    else if (!strcmp(argv[i], "-j") && i+1<argc) { json_path = argv[++i]; }
    else if (!strcmp(argv[i], "-f") && i+1<argc) { func_index = atoi(argv[++i]); }
    else if (!strcmp(argv[i], "--unique")) { id_mode = 1; }
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 1; }
  }

  if (pid <= 0 || !json_path) { usage(argv[0]); return 1; }

  size_t jlen;
  char *json = slurp(json_path, &jlen);
  if (!json) { perror("read json"); return 1; }

  uint32_t *edges_raw = NULL;
  uint32_t num_edges = 0, num_nodes = 0;
  if (extract_graph_edges(json, func_index, id_mode, &edges_raw, &num_edges, &num_nodes) != 0) {
    fprintf(stderr, "Failed to parse edges from JSON (func_index=%d)\n", func_index);
    free(json);
    return 1;
  }
  free(json);

  int fd = open(DEVICE_PATH, O_RDWR);
  if (fd < 0) { perror("open /dev/libcallsandbox"); free(edges_raw); return 1; }

  struct policy_blob hdr = {
    .pid = (uint32_t)pid,
    .num_nodes = num_nodes,
    .num_edges = num_edges,
    .id_mode = (uint32_t)id_mode
  };

  size_t blob_sz = sizeof(hdr) + num_edges * sizeof(struct edge);
  void *blob = malloc(blob_sz);
  if (!blob) { perror("malloc"); free(edges_raw); close(fd); return 1; }
  memcpy(blob, &hdr, sizeof(hdr));
  memcpy((char*)blob + sizeof(hdr), edges_raw, num_edges * sizeof(struct edge));

  if (ioctl(fd, IOCTL_LOAD_POLICY, blob) != 0) {
    perror("ioctl load policy");
    free(edges_raw);
    free(blob);
    close(fd);
    return 1;
  }

  printf("Loaded policy: pid=%d nodes=%u edges=%u mode=%s\n",
         pid, num_nodes, num_edges, id_mode?"unique":"dummy");

  free(edges_raw);
  free(blob);
  close(fd);
  return 0;
}
