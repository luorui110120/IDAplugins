
# this makefile creates the output directories for object/library files

objdir:
	@if not exist "obj$(CHKDIR)"       mkdir obj
	@if not exist "$(OBJDIR)$(CHKDIR)" mkdir $(OBJDIR)
	@if not exist "$(LIBDIR)$(CHKDIR)" mkdir $(LIBDIR)
