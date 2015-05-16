import idaapi
from idaapi import Choose2
from idaapi import Form

#<pycode(ex_formchooser)>
# --------------------------------------------------------------------------
class MainChooserClass(Choose2):
    def __init__(self, title, icon):
        Choose2.__init__(self,
                         title,
                         [ ["Item", 10] ],
                         icon=icon,
                         flags=Choose2.CH_NOIDB,
                         embedded=True, width=30, height=20)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return ["Option %d" % n]

    def OnGetSize(self):
        return 10

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_id1:
            print("Context menu on: %d" % n)

        return 0


# --------------------------------------------------------------------------
class AuxChooserClass(Choose2):
    def __init__(self, title, icon):
        Choose2.__init__(self,
                         title,
                         [ ["Item", 10] ],
                         icon=icon,
                         flags=Choose2.CH_NOIDB | Choose2.CH_MULTI,
                         embedded=True, width=30, height=20)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return ["Item %d" % n]

    def OnGetSize(self):
        t = self.form.main_current_index
        return 0 if t < 0 else t+1


# --------------------------------------------------------------------------
class MyChooserForm(Form):

    # Custom icon data
    icon_data = (
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52"
        "\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF"
        "\x61\x00\x00\x00\x7D\x49\x44\x41\x54\x78\xDA\x63\x64\xC0\x0E\xFE"
        "\xE3\x10\x67\x24\x28\x00\xD2\xFC\xF3\xAF\x36\x56\xDD\xEC\xCC\x57"
        "\x31\xF4\x20\x73\xC0\xB6\xE2\xD2\x8C\x66\x08\x5C\x2F\x8A\x01\x84"
        "\x34\x63\x73\x09\x23\xA9\x9A\xD1\x0D\x61\x44\xD7\xCC\xCF\x02\x71"
        "\xE2\xC7\x3F\xA8\x06\x62\x13\x07\x19\x42\x7D\x03\x48\xF5\xC6\x20"
        "\x34\x00\xE4\x57\x74\xFF\xE3\x92\x83\x19\xC0\x40\x8C\x21\xD8\x34"
        "\x33\x40\xA3\x91\x01\x97\x21\xC8\x00\x9B\x66\x38\x01\x33\x00\x44"
        "\x50\x92\x94\xB1\xBA\x04\x8B\x66\x9C\x99\x09\xC5\x10\x1C\xE2\x18"
        "\xEA\x01\xA3\x65\x55\x0B\x33\x14\x07\x63\x00\x00\x00\x00\x49\x45"
        "\x4E\x44\xAE\x42\x60\x82")


    def Free(self):
        del self.EChMain.form
        del self.EChAux.form

        # Call base
        Form.Free(self)

        # Free icon
        if self.icon_id != 0:
            idaapi.free_custom_icon(self.icon_id)
            self.icon_id = 0


    def __init__(self):
        # Load custom icon
        self.icon_id = idaapi.load_custom_icon(data=MyChooserForm.icon_data)
        if self.icon_id == 0:
            raise RuntimeError("Failed to load icon data!")

        self.main_current_index = -1
        self.EChMain = MainChooserClass("MainChooser", self.icon_id)
        self.EChAux  = AuxChooserClass("AuxChooser", self.icon_id)

        # Link the form to the EChooser
        self.EChMain.form = self
        self.EChAux.form = self

        Form.__init__(self, r"""STARTITEM 0
Form with choosers

    {FormChangeCb}
    Select an item in the main chooser:

    <Main chooser:{ctrlMainChooser}><Auxiliar chooser (multi):{ctrlAuxChooser}>


    <Selection:{ctrlSelectionEdit}>

""", {
            'ctrlSelectionEdit' : Form.StringInput(),
            'FormChangeCb'      : Form.FormChangeCb(self.OnFormChange),
            'ctrlMainChooser'   : Form.EmbeddedChooserControl(self.EChMain),
            'ctrlAuxChooser'    : Form.EmbeddedChooserControl(self.EChAux),
        })


    def refresh_selection_edit(self):
        if self.main_current_index < 0:
            s = "No selection in the main chooser"
        else:
            s = "Main %d" % self.main_current_index

            # Get selection in the aux chooser
            sel = self.GetControlValue(self.ctrlAuxChooser)
            if sel:
                s = "%s - Aux item(s): %s" % (s, ",".join(str(x) for x in sel))

        # Update string input
        self.SetControlValue(self.ctrlSelectionEdit, s)


    def OnFormChange(self, fid):
        if fid == -1:
            print("Initialization")
            self.refresh_selection_edit()

            # Add an item to the context menu of the main chooser
            id = self.ctrlMainChooser.AddCommand("Test", icon=self.icon_id)
            print "id=%d" % id
            if id < 0:
                print("Failed to install menu for main embedded chooser")
            else:
                self.EChMain.cmd_id1 = id

        elif fid == -2:
            print("Terminating");

        elif fid == self.ctrlMainChooser.id:
            print("main chooser selection change");
            l = self.GetControlValue(self.ctrlMainChooser);
            if not l:
                self.main_current_index = -1
            else:
                self.main_current_index = l[0]

            # Refresh auxiliar chooser
            self.RefreshField(self.ctrlAuxChooser)
            self.refresh_selection_edit()

        elif fid == self.ctrlAuxChooser.id:
            self.refresh_selection_edit()

        elif fid == self.ctrlSelectionEdit.id:
            pass
        else:
            print("unknown id %d" % fid)

        return 1

#</pycode(ex_formchooser)>

def main():
    global f
    f = MyChooserForm()
    try:
        f.Compile()
        r = f.Execute()
        print("Execute returned: %d" % r)
        f.Free()
    except Exception as e:
        print("Failed to show form: %s" % str(e))

if __name__=='__main__':
    main()