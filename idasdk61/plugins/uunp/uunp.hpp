
extern ea_t bp_gpa;      // address of GetProcAddress()
extern area_t curmod;   // current module area


// Resource extractor function

void extract_resource(const char *fname);

// Windows9x specific functions

void win9x_resolve_gpa_thunk(void);
ea_t win9x_find_thunk(ea_t ea);
void find_thunked_imports(void);
