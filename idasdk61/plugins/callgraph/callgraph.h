#ifndef __CALLGRAPH__06192009__
#define __CALLGRAPH__06192009__

#include <map>
#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
struct funcs_walk_options_t
{
  int32 version;
#define FWO_VERSION 1 // current version of options block
  int32 flags;
#define FWO_SKIPLIB       0x0001 // skip library functions
#define FWO_RECURSE_UNLIM 0x0002 // unlimited recursion
  int32 recurse_limit; // how deep to recurse (0 = unlimited)
};

//--------------------------------------------------------------------------
// function call graph creator class
class callgraph_t
{
  int node_count;

  // node id to func addr and reverse lookup
  typedef std::map<ea_t, int> ea_int_map_t;
  typedef std::map<int, ea_t> int_ea_map_t;
  ea_int_map_t ea2node;
  int_ea_map_t node2ea;

  // current node search ptr
  int  cur_node;
  char cur_text[MAXSTR];

  bool visited(ea_t func_ea, int *nid);
  int  add(ea_t func_ea);

public:
  // edge structure
  struct edge_t
  {
    int id1;
    int id2;
    edge_t(int i1, int i2): id1(i1), id2(i2) { }
    edge_t(): id1(0), id2(0) { }
  };
  typedef qlist<edge_t> edges_t;

  // edge manipulation
  typedef edges_t::iterator edge_iterator;
  void create_edge(int id1, int id2);
  edge_iterator begin_edges() { return edges.begin(); }
  edge_iterator end_edges() { return edges.end(); }
  void clear_edges();

  // find nodes by text
  int find_first(const char *text);
  int find_next();
  const char *get_findtext() { return cur_text; }
  callgraph_t();
  const int count() const { return node_count; }
  void reset();

  // node / func info
  struct funcinfo_t
  {
    qstring name;
    bgcolor_t color;
    ea_t ea;
  };
  typedef std::map<int, funcinfo_t> int_funcinfo_map_t;
  int_funcinfo_map_t cached_funcs;
  funcinfo_t *get_info(int nid);

  // function name manipulation
  const ea_t get_addr(int nid);
  const char *get_name(int nid);

  int walk_func(func_t *func, funcs_walk_options_t *o=NULL, int level=1);
private:
  edges_t edges;
};


//--------------------------------------------------------------------------
// per function call graph context
class graph_info_t
{
// Actual context variables
public:
  callgraph_t fg; // associated call graph maker
  graph_viewer_t *gv; // associated graph_view
  TForm *form; // associated TForm
  ea_t func_ea; // function ea in question
  qstring title; // the title
// Instance management
private:
  bool refresh_needed; // schedule a refresh
  typedef qlist<graph_info_t *> graphinfo_list_t;
  typedef graphinfo_list_t::iterator iterator;
  static graphinfo_list_t instances;

  graph_info_t();
  static bool find(const ea_t func_ea, iterator *out);
public:
  static graph_info_t *find(const ea_t func_ea);
  static graph_info_t *find(const char *title);
  static graph_info_t *create(ea_t func_ea);
  static void destroy(graph_info_t *gi);
  static bool get_title(ea_t func_ea, qstring *out);
  void mark_for_refresh();
  void mark_as_refreshed();
  void refresh();
  const bool is_refresh_needed() const { return refresh_needed; }
};

#endif