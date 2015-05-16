
// Common include files for IDP modules:

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <auto.hpp>
#include <queue.hpp>
#include <lines.hpp>
#include <loader.hpp>

// Current processor in the module
// It must be exported
idaman processor_t ida_module_data LPH;
