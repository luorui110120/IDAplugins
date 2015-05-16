/*
 *  This is a sample plugin module.
 *  It demonstrates how to modify ida graphs on the fly.
 *  This plugin combines sequential nodes into one.
 *  It is fully automatic.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

typedef std::map<int, areavec_t> cmbnodes_t;
static cmbnodes_t cmbnodes; // for each combined node: ranges that it represents

//--------------------------------------------------------------------------
static void removed_block(intseq_t &seq, int m)
{
  for ( int i=0; i < seq.size(); i++ )
    if ( seq[i] >= m )
      seq[i]--;
}

//--------------------------------------------------------------------------
static void combine_blocks(qflow_chart_t &fc, int n, int m)
{
  // copy successors of m to successors of n
  qbasic_block_t &bn = fc.blocks[n];
  qbasic_block_t &bm = fc.blocks[m];
  bn.succ = bm.succ;
  
  // remember that n includes m
  areavec_t &vn = cmbnodes[n];
  if ( vn.empty() )
    vn.push_back(bn);
  
  cmbnodes_t::iterator pm = cmbnodes.find(m);
  if ( pm == cmbnodes.end() )
  {
    vn.push_back(bm);
  }
  else
  {
    vn.insert(vn.end(), pm->second.begin(), pm->second.end());
    cmbnodes.erase(pm);
  }
  
  // update the end address
  bn.endEA = bm.endEA;
  
  // correct the predecessors of successors of m to be n:
  for ( int j=0; j < bn.succ.size(); j++ )
  {
    int p = bn.succ[j];
    intseq_t &bp = fc.blocks[p].pred;
    int idx = bp.index(m);
    QASSERT(30172, idx != -1);
    bp[idx] = n;
  }
  
  // remove block m
  fc.nproper--;
  fc.blocks.erase(fc.blocks.begin()+m);
  
  // renumber blocks >= m
  for ( int i=0; i < fc.size(); i++ )
  {
    removed_block(fc.blocks[i].pred, m);
    removed_block(fc.blocks[i].succ, m);
  }
  
  cmbnodes_t ninc; // updated ranges
  for ( cmbnodes_t::iterator p=cmbnodes.begin(); p != cmbnodes.end(); )
  {
    int n = p->first;
    areavec_t &vec = p->second;
    if ( n >= m )
    {
      ninc[n-1] = vec;
      cmbnodes.erase(p++);
    }
    else
    {
      ++p;
    }
  }
  cmbnodes.insert(ninc.begin(), ninc.end());
}

//--------------------------------------------------------------------------
static void combine_sequential_nodes(qflow_chart_t &fc)
{
  // calculate predecessors
  for ( int n=0; n < fc.size(); n++ )
  {
    int ns = (int)fc.nsucc(n);
    for ( int j=0; j < ns; j++ )
      fc.blocks[fc.succ(n, j)].pred.push_back(n);
  }

  // n -> m, n&m can be combined if
  //    nsucc(n) == 1
  //    npred(m) == 1
  cmbnodes.clear();
  for ( int n=0; n < fc.size(); n++ )
  {
    if ( fc.nsucc(n) != 1 )
      continue;

    int m = fc.succ(n, 0);
    if ( fc.npred(m) != 1 )
      continue;

    if ( n == m )
      continue;
  
    // ok, found a sequence, combine the blocks
    combine_blocks(fc, n, m);
    n--; // check once more
  }
}

//--------------------------------------------------------------------------
static bool generate_combined_node_text(int n, text_t &text)
{
  cmbnodes_t::iterator p = cmbnodes.find(n);
  if ( p == cmbnodes.end() )
    return false; // this node has not been combined

  // generate combine node text by generating text for all nodes in it
  areavec_t &vec = p->second;
  for ( int i=0; i < vec.size(); i++ )
  {
    ea_t ea = vec[i].startEA;
    gen_disasm_text(ea, vec[i].endEA, text, false);
  }
  return true;
}

//--------------------------------------------------------------------------
static int idaapi idp_cb(void *, int code, va_list va)
{
  switch ( code )
  {
    case processor_t::preprocess_chart:
                                // gui has retrieved a function flow chart
                                // in: qflow_chart_t *fc
                                // returns: none
                                // Plugins may modify the flow chart in this callback
      {
        qflow_chart_t *fc = va_arg(va, qflow_chart_t *);
        combine_sequential_nodes(*fc);
      }
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static int idaapi ui_cb(void *, int code, va_list va)
{
  switch ( code )
  {
    case ui_gen_idanode_text:   // cb: generate disassembly text for a node
                                // qflow_chart_t *fc
                                // int node
                                // text_t *text
                                // Plugins may intercept this event and provide
                                // custom text for an IDA graph node
                                // They may use gen_disasm_text() for that.
                                // Returns: bool text_has_been_generated
      {
        /*qflow_chart_t *fc =*/ va_arg(va, qflow_chart_t *);
        int node = va_arg(va, int);
        text_t *text = va_arg(va, text_t *);
        return generate_combined_node_text(node, *text);
      }
  }
  return 0;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
  // unload us if text mode, no graph are there
  if ( callui(ui_get_hwnd).vptr == NULL && !is_idaq() )
    return PLUGIN_SKIP;

  hook_to_notification_point(HT_IDP, idp_cb, NULL);
  hook_to_notification_point(HT_UI, ui_cb, NULL);

  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  unhook_from_notification_point(HT_IDP, idp_cb, NULL);
  unhook_from_notification_point(HT_UI, ui_cb, NULL);
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  info("This plugin is fully automatic");
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE,          // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,
  NULL,
  "Combine sequential nodes",
  NULL
};
