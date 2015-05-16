/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      Graph type definitions
 *
 *      Due to the use of STL and virtual functions, some parts of this
 *      interface might be incompatible with compilers other than BCB v6.0
 */

#ifndef __GRAPH_DEF_HPP
#define __GRAPH_DEF_HPP
#pragma pack(push, 4)

#include <algorithm>
#include <limits.h>
#include <stdio.h>
#include <math.h>

#include <loader.hpp>

class func_t;
class abstract_graph_t;

#include <pro.h>
#include <kernwin.hpp>
#include <gdl.hpp>

idaman void ida_export set_node_info(ea_t ea, int node, const bgcolor_t *pcolor, const ea_t *pea2, const char *text);
idaman char *ida_export get_node_info(ea_t ea, int node, bgcolor_t *pcolor, ea_t *pea); // must free

// Method to call graph related functions
typedef int idaapi graph_dispatcher_t(int code, ...);
idaman void ida_export set_graph_dispatcher(graph_dispatcher_t *dsp);

idaman graph_dispatcher_t ida_export_data *grentry;

//-------------------------------------------------------------------------
// node ordering in a graph
// we maintain inverse array to be able to find nodes by their numbers too
class node_ordering_t
{
  intseq_t node_by_order;
  intseq_t order_by_node;               // only if required
public:
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void idaapi clear(void)
  {
    node_by_order.clear();
    order_by_node.clear();
  }
  void idaapi resize(int n)
  {
    clear();
    node_by_order.resize(n, -1);
  }
  size_t idaapi size(void) const { return node_by_order.size(); }
  void idaapi set(int node, int num)
  {
    node_by_order[num] = node;
    if ( !order_by_node.empty() )
      order_by_node[node] = num;
  }
  bool idaapi clr(int node);
  int  idaapi node(size_t order) const { return size() > order ? node_by_order[order] : -1; }
  int  idaapi order(int node);
};

//-------------------------------------------------------------------------
struct edge_t
{
  int src;
  int dst;
  idaapi edge_t(void) {}
  idaapi edge_t(int x, int y) : src(x), dst(y) {}
  bool idaapi operator < (const edge_t &y) const
    { return src < y.src || (src == y.src && dst < y.dst); }
  bool idaapi operator == (const edge_t &y) const
    { return src == y.src && dst == y.dst; }
  bool idaapi operator != (const edge_t &y) const
    { return src != y.src || dst != y.dst; }
};
DECLARE_TYPE_AS_MOVABLE(edge_t);

typedef qvector<edge_t> edgevec_t;
typedef std::set<edge_t> edgeset_t;

//typedef int edge_type_t;        // edge types
enum edge_type_t
{
  edge_error   = 0,
  edge_tree    = 1,
  edge_forward = 2,
  edge_back    = 3,
  edge_cross   = 4,
  edge_subgraph= 5              // edge of a subgraph (used in collapse)
};

// edge type container: abstract
class edge_typer_t
{
public:
  virtual void idaapi reset(void) = 0;
  virtual edge_type_t &idaapi edge_type(int i, int j) = 0;
  edge_type_t &idaapi edge_type(const edge_t &e) { return edge_type(e.src, e.dst); }
  DEFINE_VIRTUAL_DTOR(edge_typer_t)
};

// edge type container: simple implementation
class simple_edge_typer_t : public edge_typer_t
{
public:
  typedef std::map<edge_t, edge_type_t> edge_types_t;
  edge_types_t edge_types;
  void idaapi reset(void) { edge_types.clear(); }
  edge_type_t &idaapi edge_type(int i, int j) { return edge_types[edge_t(i, j)]; }
};

//-------------------------------------------------------------------------
class graph_node_visitor_t
{
  node_set_t visited;
public:
  void idaapi reinit(void) { visited.clear(); }
  void idaapi set_visited(int n) { visited.add(n); }
  bool idaapi is_visited(int n) const { return visited.has(n); }

  virtual int  idaapi visit_node(int /*node*/) { return 0; }
  virtual bool idaapi is_forbidden_edge(int /*n*/, int /*m*/) const { return false; }

  DEFINE_VIRTUAL_DTOR(graph_node_visitor_t)
};

//-------------------------------------------------------------------------
struct graph_path_visitor_t
{
  intseq_t path;                // current path
  bool prune;                   // walk_forward(): prune := true
                                // means to stop the current path

  virtual int idaapi walk_forward(int /*node*/) { return 0; }
  virtual int idaapi walk_backward(int /*node*/) { return 0; }

  DEFINE_VIRTUAL_DTOR(graph_path_visitor_t)
};

//-------------------------------------------------------------------------
struct point_t
{
  int x, y;
  point_t(void) {}
  point_t(int _x, int _y) : x(_x), y(_y) {}
  point_t &add(const point_t &r)
  {
    x += r.x;
    y += r.y;
    return *this;
  }
  point_t &sub(const point_t &r)
  {
    x -= r.x;
    y -= r.y;
    return *this;
  }
  template <class T> void div(T d)
  {
    x /= d;
    y /= d;
  }
  void negate(void)
  {
    x = -x;
    y = -y;
  }
#ifdef VCL_H
  point_t(const TPoint &p) : x(p.x), y(p.y) {}
#endif
  bool operator ==(const point_t &r) const { return x == r.x && y == r.y; }
  bool operator !=(const point_t &r) const { return !(*this == r); }
  const char *idaapi dstr(void) const;
  size_t idaapi print(char *buf, size_t bufsize) const;
};

inline double calc_dist(point_t p, point_t q)
{
  double dx = q.x - p.x;
  double dy = q.y - p.y;
  return sqrt(dx*dx+dy*dy);
}

class pointseq_t : public qvector<point_t>
{
public:
  const char *idaapi dstr(void) const;
  size_t idaapi print(char *buf, size_t bufsize) const;
};

struct rect_t
{
  int left;
  int top;
  int right;
  int bottom;
  rect_t(void) {}
  rect_t(int l, int t, int r, int b) : left(l), top(t), right(r), bottom(b) {}
  rect_t(const point_t &p0, const point_t &p1)
    : left  (qmin(p0.x, p1.x)),
      top   (qmin(p0.y, p1.y)),
      right (qmax(p0.x, p1.x)),
      bottom(qmax(p0.y, p1.y))  {}
  int width(void) const { return right - left; }
  int height(void) const { return bottom - top; }
  void move_to(const point_t &p)
  {
    int dx  = p.x - left;
    int dy  = p.y - top;
    move_by(point_t(dx, dy));
  }
  void move_by(const point_t &p)
  {
    left   += p.x;
    right  += p.x;
    top    += p.y;
    bottom += p.y;
  }
  point_t center(void) const
  {
    return point_t((left+right)/2, (top+bottom)/2);
  }
  point_t topleft(void) const
  {
    return point_t(left, top);
  }
  point_t bottomright(void) const
  {
    return point_t(right, bottom);
  }
  void grow(int delta)
  {
    left   -= delta;
    right  += delta;
    top    -= delta;
    bottom += delta;
  }
  void intersect(const rect_t &r)
  {
    if ( left   < r.left   ) left   = r.left;
    if ( right  > r.right  ) right  = r.right;
    if ( top    < r.top    ) top    = r.top;
    if ( bottom > r.bottom ) bottom = r.bottom;
  }
  void make_union(const rect_t &r)
  {
    if ( left   > r.left   ) left   = r.left;
    if ( right  < r.right  ) right  = r.right;
    if ( top    > r.top    ) top    = r.top;
    if ( bottom < r.bottom ) bottom = r.bottom;
  }
  bool empty(void) const
  {
    return left >= right || top >= bottom;
  }
  bool is_intersection_empty(const rect_t &r) const
  {
    return left   >= r.right
        || right  <= r.left
        || top    >= r.bottom
        || bottom <= r.top;
  }
  bool contains(const point_t &p) const
  {
    return left <= p.x
        && right > p.x
        && top <= p.y
        && bottom > p.y;
  }
  int area(void) const { return width()*height(); }
  bool idaapi operator == (const rect_t &r) const
  {
    return left   == r.left
        && right  == r.right
        && top    == r.top
        && bottom == r.bottom;
  }
  bool idaapi operator != (const rect_t &r) const { return !(*this == r); }
  bool idaapi operator < (const rect_t &r) const;
#ifdef VCL_H
  const TRect &operator()(void) const { return *(TRect *)this; };
        TRect &operator()(void)       { return *(TRect *)this; };
  rect_t(const TRect &r) : left(r.left), top(r.top), right(r.right), bottom(r.bottom) {}
#endif
};


//---------------------------------------------------------------------------
struct TPointDouble
{
  double x, y;
  TPointDouble(void) {}
  TPointDouble(double a, double b) : x(a), y(b) {}
  TPointDouble(const point_t &r) : x(r.x), y(r.y) {}
  void add(const TPointDouble &r)
  {
    x += r.x;
    y += r.y;
  }
  void sub(const TPointDouble &r)
  {
    x -= r.x;
    y -= r.y;
  }
  void negate(void)
  {
    x = -x;
    y = -y;
  }
  template <class T> void div(T d)
  {
    x /= d;
    y /= d;
  }
  bool operator ==(const TPointDouble &r) const { return x == r.x && y == r.y; }
  bool operator !=(const TPointDouble &r) const { return !(*this == r); }
};

//---------------------------------------------------------------------------
typedef int layout_type_t;
const layout_type_t
  layout_none    = 0,
  layout_digraph = 1,
  layout_tree    = 2,
  layout_circle  = 3;

struct edge_info_t
{
  int color;
  int width;
  int srcoff;   // source: edge port offset from the left
  int dstoff;   // destination: edge port offset from the left
  pointseq_t layout;
  void idaapi reverse_layout(void) { std::reverse(&layout[0], &layout[layout.size()]); }
  void idaapi add_layout_point(point_t p);
       idaapi edge_info_t(void) : color(-1), width(1), srcoff(-1), dstoff(-1) {}
};

// edge layout point
struct edge_layout_point_t
{
  int pidx;      // index into edge_info_t::layout
  edge_t e;
  idaapi edge_layout_point_t(void) : pidx(-1), e(-1, -1) {}
  idaapi edge_layout_point_t(const edge_layout_point_t &r) : pidx(r.pidx), e(r.e) {}
  idaapi edge_layout_point_t(const edge_t &_e, int _pidx) : pidx(_pidx), e(_e) {}
  int idaapi compare(const edge_layout_point_t &r) const
  {
    if ( e < r.e )
      return -1;
    if ( r.e < e )
      return 1;
    return pidx - r.pidx;
  }
  bool idaapi operator == (const edge_layout_point_t &r) const
  {
    return pidx == r.pidx && e == r.e;
  }
  bool idaapi operator != (const edge_layout_point_t &r) const
  {
    return !(*this == r);
  }
};

struct selection_item_t
{
  bool is_node;
  int node;
  edge_layout_point_t elp;
  idaapi selection_item_t(void) {}
  idaapi selection_item_t(int n) : is_node(true), node(n) {}
  idaapi selection_item_t(edge_layout_point_t &_elp)
    : is_node(false), node(-1), elp(_elp) {}
  idaapi selection_item_t(edge_t e, int idx)
    : is_node(false), node(-1), elp(e, idx) {}
  idaapi selection_item_t(class graph_item_t &);
  int idaapi compare(const selection_item_t &r) const
  {
    if ( is_node != r.is_node )
      return is_node - r.is_node;
    if ( is_node )
      return node - r.node;
    return elp.compare(r.elp);
  }
  bool idaapi operator == (const selection_item_t &r) const
    { return compare(r) == 0; }
  bool idaapi operator < (const selection_item_t &r) const
    { return compare(r) < 0; }
};


// selection in a graph: list of nodes and edge layout points.
// this selection is used to move a subgraph on the screen.
struct screen_graph_selection_t : std::set<selection_item_t>
{
  bool idaapi has(const selection_item_t &item) const
    { return (const_iterator)find(item) != end(); }
  void idaapi add(const screen_graph_selection_t &s)
  {
    for ( screen_graph_selection_t::const_iterator p=s.begin(); p != s.end(); ++p )
      insert(*p);
  }
  void idaapi sub(const screen_graph_selection_t &s)
  {
    for ( screen_graph_selection_t::const_iterator p=s.begin(); p != s.end(); ++p )
      erase(*p);
  }
  void idaapi add_node(int n) { insert(selection_item_t(n)); }
  void idaapi del_node(int n) { erase(selection_item_t(n)); }
  void idaapi add_point(edge_t e, int idx) { insert(selection_item_t(e, idx)); }
  void idaapi del_point(edge_t e, int idx) { erase(selection_item_t(e, idx)); }
};

struct edge_segment_t
{
  edge_t e;
  int nseg;
  int x0, x1;
  size_t idaapi length(void) const { return abs(x1-x0); }
  bool idaapi toright(void) const { return x1 > x0; } // horizontal segment to the right
  bool idaapi operator < (const edge_segment_t &r) const
  {
    return e < r.e;
/*    // longest edges first
    int ll =   x1 -   x0; if ( ll < 0 ) ll = -ll;
    int rl = r.x1 - r.x0; if ( rl < 0 ) rl = -rl;
    if ( rl < ll )
      return true;
    if ( rl == ll )
      return e < r.e;
    return false;*/
  }
};

//---------------------------------------------------------------------------
enum graph_item_type_t
{           //                       valid graph_item_t fields:
  git_none, // nothing
  git_edge, // edge                  e, n (n is farthest edge endpoint)
  git_node, // node title            n
  git_tool, // node title button     n, b
  git_text, // node text             n, p
  git_elp,  // edge layout point     elp
};

class graph_item_t
{
public:
  graph_item_type_t type;
  edge_t e;             // edge source and destination
  int n;                // node number
  int b;                // button number
  point_t p;            // text coordinates in the node
  edge_layout_point_t elp;// edge layout point
  bool operator == (const graph_item_t &r) const;
  bool is_node(void) const { return type >= git_node && type <= git_text; }
  bool is_edge(void) const { return type == git_edge || type == git_elp; }
};

//-------------------------------------------------------------------------
struct interval_t
{
  int x0, x1;           // x0 always <= x1, otherwise the interval is empty
  bool empty(void) const { return x0 < x1; }
  void intersect(const interval_t &r)
  {
    if ( x0 < r.x0 ) x0 = r.x0;
    if ( x1 > r.x1 ) x1 = r.x1;
  }
  void make_union(const interval_t &r)
  {
    if ( x0 > r.x0 ) x0 = r.x0;
    if ( x1 < r.x1 ) x1 = r.x1;
  }
  void move_by(int shift)
  {
    x0 += shift;
    x1 += shift;
  }
  interval_t(void) {}
  interval_t(int y0, int y1)
  {
    x0 = qmin(y0, y1);
    x1 = qmax(y0, y1);
  }
  interval_t(const edge_segment_t &s)
  {
    x0 = qmin(s.x0, s.x1);
    x1 = qmax(s.x0, s.x1);
  }
  int length(void) const { return x1 - x0; }
  bool contains(int x) const { return x0 <= x && x <= x1; }
  bool operator ==(const interval_t &r) const { return x0 == r.x0 && x1 == r.x1; }
  bool operator !=(const interval_t &r) const { return !(*this == r); }
};


typedef std::set<edge_segment_t> edge_segments_t;
typedef std::vector<edge_segment_t> edge_seg_vec_t;
typedef std::vector<edge_segments_t> edge_segs_vec_t;

typedef std::map<edge_t, edge_info_t> edge_infos_t;

//-------------------------------------------------------------------------
struct row_info_t
{
  intseq_t nodes;       // list of nodes at the row
  int top;              // top y coord of the row
  int bottom;
  int height(void) const { return bottom - top; }
  row_info_t(void) : top(0) {}
};
typedef qvector<row_info_t> graph_row_info_t;

static const int ygap = 30;
static const int xgap = 10;
static const int arrow_height = 10;
static const int arrow_width = 8;

struct graph_location_info_t;
class graph_visitor_t;

//-------------------------------------------------------------------------
// abstract graph interface
class abstract_graph_t : public gdl_graph_t
{
  void idaapi find_entries(node_set_t &entries) const;
  void idaapi depth_first(int root, struct depth_first_info_t &di) const;
  size_t idaapi remove_reachable(int n, node_set_t &s) const;
  int    idaapi longest_path(int n, intseq_t &tops, int row_height) const;
  size_t idaapi sort_layer_nodes(const row_info_t &r1,
                         const intmap_t &lpi1,
                         row_info_t &r2,
                         intmap_t &lpi2,
                         bool ispred) const;
  size_t idaapi calc_cross_num(const intseq_t &r1,
                       const intseq_t &r2,
                       const intmap_t &lpi1,
                       bool ispred) const;
  size_t idaapi num_crossings(const graph_row_info_t &gri, const array_of_intmap_t &nodepi) const;
  int    idaapi calc_x_coord(const row_info_t &ri, int idx, bool ispred, int first_added_node) const;
  void   idaapi try_move_down(intseq_t &tops, int n, int row_height) const;

protected:
  // returns one entry point for each connected component
  void idaapi get_connected_components(intseq_t &entries) const;

  // find longest pathes from the entries. take into account node heights
  // if row_height > 0, then use it instead of real node heights
  // return max distance found
  int idaapi calc_longest_pathes(
        const node_set_t &entries,
        intseq_t &tops,
        int row_height) const;
  // move entry nodes down as much as possible
  void idaapi move_nodes_down(
        intseq_t &tops,
        const node_ordering_t &post,
        int first_reverser_node,
        int row_height) const;
  // create graph row info from 'tops'
  void idaapi create_graph_row_info(
        const intseq_t &tops,
        graph_row_info_t &gri,
        int graph_height) const;
  // calc height of each row
  void idaapi calc_row_heights(graph_row_info_t &gri) const;
  // minimize crossings
  void idaapi minimize_crossings(graph_row_info_t &gri) const;
  // calculate x coords of all nodes
  void idaapi set_x_coords(
        const graph_row_info_t &gri,
        const node_set_t &selfrefs,
        int first_added_node);
  // gather information about all edge segments
  void idaapi gather_edge_segments(
        const graph_row_info_t &gri,
        edge_segs_vec_t &ges) const;
  // make all edges rectangular
  void idaapi make_rect_edges(
        graph_row_info_t &gri,
        const edge_segs_vec_t &ges,
        int first_reverser_node);
  // assigned ports to edges
  void idaapi assign_edge_ports(
        const graph_row_info_t &gri,
        const node_set_t &selfrefs);
  void idaapi recalc_edge_widths(
        const edgeset_t &back_edges,
        const edge_infos_t &self_edges);
  // clear layout information in the graph
  void idaapi clear_layout_info(void);
  void idaapi depth_first(
        node_ordering_t *pre,
        node_ordering_t *post,
        edge_typer_t *et) const;
//  void breadth_first(node_ordering_t &breadth) const;
  void idaapi create_spanning_tree(
        edge_typer_t *et,
        node_set_t *entries,
        edgeset_t *back_edges,
        node_ordering_t *pre,
        node_ordering_t *post) const;
  void idaapi tree_layout(edge_typer_t &et, const node_set_t &entries);

  // is there a path from M to N which terminates with a back edge to N?
  bool idaapi path_back(const array_of_node_set_t &domin, int m, int n) const;
  bool idaapi path_back(edge_typer_t &et, int m, int n) const;

  // visit nodes starting from 'node', depth first
  int idaapi visit_nodes(int node, graph_node_visitor_t &gv) const;
  // visit paths starting from 'node'
  int idaapi visit_paths(int node, graph_path_visitor_t &gv) const;

public:
  qstring title;
  bool rect_edges_made;
  layout_type_t current_layout;
  point_t circle_center;                // for layout_circle
  int circle_radius;                    // for layout_circle
  hook_cb_t *callback;                  // user-defined callback
  void *callback_ud;

  idaapi abstract_graph_t(void)
    : rect_edges_made(false),
      current_layout(layout_none),
      callback(NULL),
      callback_ud(NULL)
  {}
  DEFINE_VIRTUAL_DTOR(abstract_graph_t)
  void idaapi clear(void);
  void idaapi dump_graph(void) const;
  bool idaapi calc_bounds(rect_t *r);
  bool idaapi calc_fitting_params(
        const rect_t &area,
        graph_location_info_t *gli,
        double max_zoom);
  int idaapi for_all_nodes_edges(graph_visitor_t &nev, bool visit_nodes=true);
  // get edge ports - fills s, d arguments and returns edge_info_t
  const edge_info_t *idaapi get_edge_ports(
        edge_t e,
        point_t &s,
        point_t &d) const;
  // add edges from/to the node
  void idaapi add_node_edges(edgeset_t &dlist, int node);
  const rect_t &idaapi nrect(int n) const
    { return (CONST_CAST(abstract_graph_t *)(this))->nrect(n); }
  const edge_info_t *idaapi get_edge(edge_t e) const
    { return (CONST_CAST(abstract_graph_t *)(this))->get_edge(e); }
  virtual rect_t &idaapi nrect(int n) = 0;
  virtual edge_info_t *idaapi get_edge(edge_t e) = 0;
  virtual abstract_graph_t *idaapi clone(void) const = 0;

  bool idaapi create_tree_layout(void);
  bool idaapi create_circle_layout(point_t p, int radius);

  void set_callback(hook_cb_t *_callback, void *_ud)
  {
    callback = _callback;
    callback_ud = _ud;
  }
  int vgrcall(int code, va_list va)
  {
    if ( callback != NULL )
      return callback(callback_ud, code, va);
    return 0;
  }
  int grcall(int code, ...)
  {
    va_list va;
    va_start(va, code);
    int result = vgrcall(code, va);
    va_end(va);
    return result;
  }
};

// For some reason GCC insists on putting the vtable into object files,
// even though we only use mutable_graph_t by pointer.
// This looks like a linker bug. We fix it by declaring functions as pure virtual
// when plugins are compiled.
#if defined(__GNUC__) && (!defined(__IDP__) || !defined(__UI__))  // compiling a plugin or the kernel with gcc?
#define GCC_PUREVIRT = 0
#else
#define GCC_PUREVIRT
#endif

//-------------------------------------------------------------------------
class mutable_graph_t : public abstract_graph_t
{
  typedef abstract_graph_t inherited;
  typedef std::map<int, int> destset_t;
  friend int idaapi graph_dispatcher(int code, ...);
  int idaapi _find_subgraph_node(int group, int n) const;
  void idaapi collapse_edges(const intset_t &nodes, int group);
  void idaapi del_node_keep_edges(int n);
  void idaapi add_dest(destset_t &ne, edge_t e, int g);
  void idaapi reverse_edges(
        const edgeset_t &back_edges,
        edge_infos_t &self_edges,
        node_set_t &entries);
  void idaapi layout_self_reference_edges(const edge_infos_t &selfrefs);
  void idaapi restore_edges(int first_reserver_node, bool failed);

  void idaapi add_layer_nodes(graph_row_info_t &gri, intseq_t &tops);
  void idaapi del_layer_nodes(graph_row_info_t &gri, int first_added_node);

public:
  uval_t gid;                   // graph id - unique for the database
                                // for flowcharts it is equal to the function startEA
  intseq_t belongs;             // the subgraph the node belongs to
                                // INT_MAX means that the node doesn't exist
                                // sign bit means collapsed node
  boolvec_t is_group;           // is group node?
  // groups: original edges without considering any group info
  array_of_intseq_t org_succs;
  array_of_intseq_t org_preds;

  array_of_intseq_t succs;
  array_of_intseq_t preds;
  typedef qvector<rect_t> node_layout_t;
  node_layout_t nodes;
  edge_infos_t edges;

  idaapi mutable_graph_t(uval_t id) : gid(id) {}
  idaapi mutable_graph_t(const abstract_graph_t &g, uval_t id);
  DEFINE_VIRTUAL_DTOR(mutable_graph_t)
  int  idaapi size(void) const { return int(succs.size()); }
  int  idaapi node_qty(void) const;
  void idaapi clear(void);
  bool idaapi empty(void) const;
  bool idaapi exists(int node) const { return is_visible_node(node); }
#define COLLAPSED_NODE 0x80000000
  int  idaapi get_node_representative(int node);
  int  idaapi get_node_group(int node) const { return (belongs[node] & ~COLLAPSED_NODE); }
  void idaapi set_node_group(int node, int group) { belongs[node] = group | (belongs[node] & COLLAPSED_NODE); }
  bool idaapi is_deleted_node(int node) const { return belongs[node] == INT_MAX; }
  void idaapi set_deleted_node(int node) { belongs[node] = INT_MAX; }
  bool idaapi is_subgraph_node(int node) const { return get_node_group(node) != node; }
  bool idaapi is_group_node(int node) const { return is_group[node]; }
  bool idaapi is_simple_node(int node) const { return !is_group_node(node); }
  bool idaapi is_collapsed_node(int node) const { return (belongs[node] & COLLAPSED_NODE) != 0; }
  bool idaapi is_uncollapsed_node(int node) const { return is_group_node(node) && !is_collapsed_node(node); }
  bool idaapi is_visible_node(int node) const;
  bool idaapi groups_are_present(void) const;
  // iterate subgraph nodes, return -1 at the end
  int  idaapi get_first_subgraph_node(int group) const { return _find_subgraph_node(group, 0); }
  int  idaapi get_next_subgraph_node(int group, int current) const { return _find_subgraph_node(group, current+1); }
  void idaapi insert_visible_nodes(intset_t &nodes, int group) const;
  void idaapi insert_simple_nodes(intset_t &nodes, int group) const;
  bool idaapi check_new_group(const intset_t &nodes, intset_t &refined);
  int  idaapi create_group(const intset_t &nodes); // -1 - error
  bool idaapi delete_group(int group);
  bool idaapi change_group_visibility(int group, bool expand);
  bool idaapi change_visibility(const intset_t &nodes, bool expand);
  void idaapi recalc_edges(void);
  int  idaapi nsucc(int b) const  { return (int)succs[b].size(); }
  int  idaapi npred(int b) const  { return (int)preds[b].size(); }
  int  idaapi succ(int b, int i) const { return succs[b][i]; }
  int  idaapi pred(int b, int i) const { return preds[b][i]; }
  const intseq_t &idaapi succset(int b) const { return succs[b]; }
  const intseq_t &idaapi predset(int b) const { return preds[b]; }

  void idaapi reset(void) { resize(0); }
  virtual bool idaapi redo_layout(void) GCC_PUREVIRT;
  virtual void idaapi resize(int n) GCC_PUREVIRT;
  virtual int  idaapi add_node(const rect_t *r) GCC_PUREVIRT;
  virtual ssize_t idaapi del_node(int n) GCC_PUREVIRT;  // returns number of deleted edges
  virtual bool idaapi add_edge(int i, int j, const edge_info_t *ei) GCC_PUREVIRT;
  virtual bool idaapi del_edge(int i, int j) GCC_PUREVIRT;  // true: found and deleted the edge
  virtual bool idaapi replace_edge(int i, int j, int x, int y) GCC_PUREVIRT;
  virtual bool idaapi refresh(void) GCC_PUREVIRT;
  virtual mutable_graph_t *idaapi clone(void) const GCC_PUREVIRT;

  // get node rectangle
  const rect_t &idaapi nrect(int n) const
    { return (CONST_CAST(mutable_graph_t *)(this))->nrect(n); }
  rect_t &idaapi nrect(int n);
  virtual edge_info_t *idaapi get_edge(edge_t e) GCC_PUREVIRT;

  virtual bool idaapi set_nrect(int n, const rect_t &r) GCC_PUREVIRT;
  virtual bool idaapi set_edge(edge_t e, const edge_info_t *ei) GCC_PUREVIRT;

  bool idaapi create_digraph_layout(void);

  void idaapi del_custom_layout(void);
  bool idaapi get_custom_layout(void);
  void idaapi set_custom_layout(void) const;
  bool idaapi get_graph_groups(void);
  void idaapi set_graph_groups(void) const;
  virtual ea_t idaapi calc_group_ea(const intset_t& /*nodes*/) { return BADADDR; }

  point_t idaapi calc_center_of(const intset_t &nodes) const;
  void idaapi move_to_same_place(const intset_t &collapsing_nodes, point_t p);
  void idaapi move_grouped_nodes(const intset_t &groups, const mutable_graph_t *ng);

  virtual bool idaapi is_user_graph() { return false; }
};

//-------------------------------------------------------------------------
class graph_visitor_t
{
protected:
  abstract_graph_t *g;
  virtual int idaapi visit_node(int n, rect_t &r) = 0;
  virtual int idaapi visit_edge(edge_t e, edge_info_t *ei) = 0;
  friend int idaapi abstract_graph_t::for_all_nodes_edges(graph_visitor_t &nev, bool visit_nodes);
};

//-------------------------------------------------------------------------
enum graph_notification_t
{
  // Callbacks called by IDA (plugins can hook to them):
  grcode_calculating_layout,  // calculating user-defined graph layout
                              // in: mutable_graph_t *g
                              // out: 0-not implemented
                              //      1-graph layout calculated by the plugin

  grcode_layout_calculated,   // graph layout calculated
                              // in: mutable_graph_t *g
                              //     bool layout_succeeded
                              // out: must return 0

  grcode_changed_graph,       // new graph has been set
                              // in: mutable_graph_t *g
                              // out: must return 0

  grcode_changed_current,     // a new graph node became the current node
                              // in:  graph_viewer_t *gv
                              //      int curnode
                              // out: 0-ok, 1-forbid to change the current node

  grcode_clicked,             // graph is being clicked
                              // in:  graph_viewer_t *gv
                              //      selection_item_t *current_item1
                              //      graph_item_t *current_item2
                              // out: 0-ok, 1-ignore click
                              // this callback allows you to ignore some clicks.
                              // it occurs too early, internal graph variables are not updated yet
                              // current_item1, current_item2 point to the same thing
                              // item2 has more information.
                              // see also: kernwin.hpp, custom_viewer_click_t

  grcode_dblclicked,          // a graph node has been double clicked
                              // in:  graph_viewer_t *gv
                              //      selection_item_t *current_item
                              // out: 0-ok, 1-ignore click

  grcode_creating_group,      // a group is being created
                              // in:  mutable_graph_t *g
                              //      intset_t *nodes
                              // out: 0-ok, 1-forbid group creation

  grcode_deleting_group,      // a group is being deleted
                              // in:  mutable_graph_t *g
                              //      int old_group
                              // out: 0-ok, 1-forbid group deletion

  grcode_group_visibility,    // a group is being collapsed/uncollapsed
                              // in:  mutable_graph_t *g
                              //      int group
                              //      bool expand
                              // out: 0-ok, 1-forbid group modification

  grcode_gotfocus,            // a graph viewer got focus
                              // in:  graph_viewer_t *gv
                              // out: must return 0

  grcode_lostfocus,           // a graph viewer lost focus
                              // in:  graph_viewer_t *gv
                              // out: must return 0

  grcode_user_refresh,        // refresh user-defined graph node number and edges
                              // in:  mutable_graph_t *g
                              // out: success

  grcode_user_gentext,        // generate text for user-defined graph nodes
                              // in:  mutable_graph_t *g
                              // out: success

  grcode_user_text,           // retrieve text for user-defined graph node
                              // in:  mutable_graph_t *g
                              //      int node
                              //      const char **result
                              //      bgcolor_t *bg_color (maybe NULL)
                              // out: success, result must be filled
                              // NB: do not use anything calling GDI!

  grcode_user_size,           // calculate node size for user-defined graph
                              // in:  mutable_graph_t *g
                              //      int node
                              //      int *cx
                              //      int *cy
                              // out: 0-did not calculate, ida will use node text size
                              //      1-calculated. ida will add node title to the size

  grcode_user_title,          // render node title of a user-defined graph
                              // in:  mutable_graph_t *g
                              //      int node
                              //      rect_t *title_rect
                              //      int title_bg_color
                              //      HDC dc
                              // out: 0-did not render, ida will fill it with title_bg_color
                              //      1-rendered node title

  grcode_user_draw,           // render node of a user-defined graph
                              // in:  mutable_graph_t *g
                              //      int node
                              //      rect_t *node_rect
                              //      HDC dc
                              // out: 0-not rendered, 1-rendered
                              // NB: draw only on the specified DC and nowhere else!

  grcode_user_hint,           // retrieve hint for the user-defined graph
                              // in:  mutable_graph_t *g
                              //      int mousenode
                              //      int mouseedge_src
                              //      int mouseedge_dst
                              //      char **hint
                              // 'hint' must be allocated by qalloc() or qstrdup()
                              // out: 0-use default hint, 1-use proposed hint

  grcode_destroyed,           // graph is being destroyed
                              // in:  mutable_graph_t *g
                              // out: must return 0

  // Callbacks callable from plugins (see inline functions below):

  grcode_create_graph_viewer = 256,
  grcode_get_graph_viewer,
  grcode_get_viewer_graph,
  grcode_create_mutable_graph,
  grcode_set_viewer_graph,
  grcode_refresh_viewer,
  grcode_fit_window,
  grcode_get_curnode,
  grcode_center_on,
  grcode_set_gli,
  grcode_add_menu_item,
  grcode_del_menu_item,
  grcode_get_selection,
  grcode_del_custom_layout,
  grcode_set_custom_layout,
  grcode_set_graph_groups,
  grcode_clear,
  grcode_create_digraph_layout,
  grcode_create_tree_layout,
  grcode_create_circle_layout,
  grcode_get_node_representative,
  grcode_find_subgraph_node,
  grcode_create_group,
  grcode_get_custom_layout,
  grcode_get_graph_groups,
  grcode_empty,
  grcode_is_visible_node,
  grcode_delete_group,
  grcode_change_group_visibility,
  grcode_set_edge,
  grcode_node_qty,
  grcode_nrect,
  grcode_set_titlebar_height,
  grcode_create_user_graph_place,
  grcode_create_disasm_graph1,
  grcode_create_disasm_graph2,
};

#ifndef __UI__

class TForm; //lint -esym(1075, TForm) Ambiguous reference to symbol
typedef TCustomControl graph_viewer_t;

inline graph_viewer_t *idaapi create_graph_viewer(
        TForm *parent,
        uval_t id,
        hook_cb_t *callback,
        void *ud,
        int title_height)
{
  graph_viewer_t *gv = NULL;
  grentry(grcode_create_graph_viewer, parent, &gv, id, callback, ud, title_height);
  return gv;
}

inline graph_viewer_t *idaapi get_graph_viewer(TForm *parent)                { graph_viewer_t *gv = NULL; grentry(grcode_get_graph_viewer, parent, &gv); return gv; }
inline mutable_graph_t *idaapi get_viewer_graph(graph_viewer_t *gv)          { mutable_graph_t *g = NULL; grentry(grcode_get_viewer_graph, gv, &g); return g; }
inline mutable_graph_t *idaapi create_mutable_graph(uval_t id)               { mutable_graph_t *g = NULL; grentry(grcode_create_mutable_graph, id, &g); return g; } // empty graph
inline mutable_graph_t *idaapi create_disasm_graph(ea_t ea)                  { mutable_graph_t *g = NULL; grentry(grcode_create_disasm_graph1, ea, &g); return g; } // function flowchart
inline mutable_graph_t *idaapi create_disasm_graph(const areavec_t &ranges)  { mutable_graph_t *g = NULL; grentry(grcode_create_disasm_graph2, &ranges, &g); return g; } // arbitrary flowchart
inline void idaapi set_viewer_graph(graph_viewer_t *gv, mutable_graph_t *g)  {        grentry(grcode_set_viewer_graph, gv, g); }
inline void idaapi refresh_viewer(graph_viewer_t *gv)                        {        grentry(grcode_refresh_viewer, gv); }
inline void idaapi viewer_fit_window(graph_viewer_t *gv)                     {        grentry(grcode_fit_window, gv); }
inline int  idaapi viewer_get_curnode(graph_viewer_t *gv)                    { return grentry(grcode_get_curnode, gv); }
inline void idaapi viewer_center_on(graph_viewer_t *gv, int node)            {        grentry(grcode_center_on, gv, node); }
inline void idaapi viewer_set_gli(graph_viewer_t *gv,
                                  const graph_location_info_t *gli)          { grentry(grcode_set_gli, gv, gli); }
inline bool idaapi viewer_add_menu_item(graph_viewer_t *gv,
                                        const char *title,
                                        menu_item_callback_t *callback,
                                        void *ud,
                                        const char *hotkey,
                                        int flags)                           { return grentry(grcode_add_menu_item, gv, title, callback, ud, hotkey, flags); }
inline bool idaapi viewer_del_menu_item(graph_viewer_t *gv,
                                        const char *title)                   { return grentry(grcode_del_menu_item, gv, title); }
inline bool idaapi viewer_get_selection(graph_viewer_t *gv,
                                        screen_graph_selection_t *sgs)       { return grentry(grcode_get_selection, gv, sgs); }
inline int  idaapi viewer_set_titlebar_height(graph_viewer_t *gv,
                                        int height)                          { return grentry(grcode_set_titlebar_height, gv, height); }

inline void idaapi mutable_graph_t::del_custom_layout(void)                  {        grentry(grcode_del_custom_layout, this); }
inline void idaapi mutable_graph_t::set_custom_layout(void) const            {        grentry(grcode_set_custom_layout, this); }
inline void idaapi mutable_graph_t::set_graph_groups(void) const             {        grentry(grcode_set_graph_groups, this); }
inline void idaapi mutable_graph_t::clear(void)                              {        grentry(grcode_clear, this); }
inline bool idaapi mutable_graph_t::create_digraph_layout(void)              { return grentry(grcode_create_digraph_layout, this); }
inline bool idaapi abstract_graph_t::create_tree_layout(void)                { return grentry(grcode_create_tree_layout, this); }
inline bool idaapi abstract_graph_t::create_circle_layout(point_t c, int radius) { return grentry(grcode_create_circle_layout, this, c.x, c.y, radius); }
inline int  idaapi mutable_graph_t::get_node_representative(int node)        { return grentry(grcode_get_node_representative, this, node); }
inline int  idaapi mutable_graph_t::_find_subgraph_node(int gr, int n) const { return grentry(grcode_find_subgraph_node, this, gr, n); }
inline int  idaapi mutable_graph_t::create_group(const intset_t &nodes)      { return grentry(grcode_create_group, this, &nodes); }
inline bool idaapi mutable_graph_t::get_custom_layout(void)                  { return grentry(grcode_get_custom_layout, this); }
inline bool idaapi mutable_graph_t::get_graph_groups(void)                   { return grentry(grcode_get_graph_groups, this); }
inline bool idaapi mutable_graph_t::empty(void) const                        { return grentry(grcode_empty, this); }
inline bool idaapi mutable_graph_t::is_visible_node(int node) const          { return grentry(grcode_is_visible_node, this, node); }
inline bool idaapi mutable_graph_t::delete_group(int group)                  { return grentry(grcode_delete_group, this, group); }
inline bool idaapi mutable_graph_t::change_group_visibility(int gr, bool exp){ return grentry(grcode_change_group_visibility, this, gr, exp); }
inline bool idaapi mutable_graph_t::set_edge(edge_t e, const edge_info_t *ei){ return grentry(grcode_set_edge, this, e.src, e.dst, ei); }
inline int  idaapi mutable_graph_t::node_qty(void) const                     { return grentry(grcode_node_qty, this); }
inline rect_t &idaapi mutable_graph_t::nrect(int n)                          { rect_t *r; grentry(grcode_nrect, this, n, &r); return *r; }

// The following structure is returned by get_custom_viewer_place() if the first
// parameter is a graph viewer.
struct user_graph_place_t : public place_t
{
  int node;
};

// if you need a copy of this structure for your own purposes, use this:
// (it returns a pointer to static storage)
inline user_graph_place_t *create_user_graph_place(int node, int lnnum)      { user_graph_place_t *r; grentry(grcode_create_user_graph_place, node, lnnum, &r); return r; }

#endif  // UI

#pragma pack(pop)
#endif
