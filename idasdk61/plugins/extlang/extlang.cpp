/*
        This is a sample plugin. It illustrates

          how to register a thid party language interpreter

*/

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <expr.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
static bool idaapi compile(     // Compile an expression
        const char *name,       // in: name of the function which will
                                //     hold the compiled expression
        ea_t current_ea,        // in: current address. if unknown then BADADDR
        const char *expr,       // in: expression to compile
        char *errbuf,           // out: error message if compilation fails
        size_t errbufsize)      // in: size of the error buffer
{                               // Returns: success
  qnotused(name);
  qnotused(current_ea);
  qnotused(expr);
  qnotused(errbuf);
  qnotused(errbufsize);
  // our toy interpreter doesn't support separate compilation/evaluation
  // some entry fields in ida won't be useable (bpt conditions, for example)
  qstrncpy(errbuf, "compilation error", errbufsize);
  return false;
}

//--------------------------------------------------------------------------
static bool idaapi run(         // Evaluate a previously compiled expression
        const char *name,       // in: function to run
        int nargs,              // in: number of input arguments
        const idc_value_t args[], // in: input arguments
        idc_value_t *result,    // out: function result
        char *errbuf,           // out: error message if evaluation fails
        size_t errbufsize)      // in: size of the error buffer
{                               // Returns: success
  qnotused(name);
  qnotused(nargs);
  qnotused(args);
  qnotused(result);
  qnotused(errbuf);
  qnotused(errbufsize);
  qstrncpy(errbuf, "evaluation error", errbufsize);
  return false;
}

//--------------------------------------------------------------------------
static bool idaapi calcexpr(    // Compile and evaluate expression
        ea_t current_ea,        // in: current address. if unknown then BADADDR
        const char *expr,       // in: expression to evaluation
        idc_value_t *rv,        // out: expression value
        char *errbuf,           // out: error message if evaluation fails
        size_t errbufsize)      // in: size of the error buffer
{                               // Returns: success
  qnotused(current_ea);
  // we know to parse and decimal and hexadecimal numbers
  int radix = 10;
  const char *ptr = skipSpaces(expr);
  bool neg = false;
  if ( *ptr == '-' )
  {
    neg = true;
    ptr = skipSpaces(ptr+1);
  }
  if ( *ptr == '0' && *(ptr+1) == 'x' )
  {
    radix = 16;
    ptr += 2;
  }
  sval_t value = 0;
  while ( radix==10 ? qisdigit(*ptr) : qisxdigit(*ptr) )
  {
    int d = *ptr <= '9' ? *ptr-'0' : qtolower(*ptr)-'a'+10;
    value *= radix;
    value += d;
    ptr++;
  }
  if ( neg )
    value = -value;
  ptr = skipSpaces(ptr);
  if ( *ptr != '\0' )
  {
    msg("EVAL FAILED: %s\n", expr);
    qstrncpy(errbuf, "syntax error", errbufsize);
    return false;
  }

  // we have the result, store it in the return value
  rv->clear();
  rv->num = value;
  msg("EVAL %d: %s\n", value, expr);
  return true;
}

//--------------------------------------------------------------------------
static extlang_t el =
{
  sizeof(extlang_t),            // Size of this structure
  0,                            // Language features, currently 0
  "extlang sample",             // Language name

  compile,
  run,
  calcexpr
};

//--------------------------------------------------------------------------
int idaapi init(void)
{
  if ( install_extlang(&el) )
  {
    return PLUGIN_KEEP;
  }
  else
  {
    msg("extlang: install_extlang() failed\n");
    return PLUGIN_SKIP;
  }
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
  remove_extlang(&el);
}

//--------------------------------------------------------------------------
void idaapi run(int) // won't be called
{
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX|PLUGIN_HIDE,// plugin flags:
                        //   - we want to be in the memory from the start
                        //   - plugin is hidden
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "Sample third party language", // the preferred short name of the plugin
  NULL                  // the preferred hotkey to run the plugin
};
