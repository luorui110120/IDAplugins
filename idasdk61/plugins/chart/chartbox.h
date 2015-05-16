//---------------------------------------------------------------------------
#ifndef chartboxH
#define chartboxH
//---------------------------------------------------------------------------
#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>
#include <TeEngine.hpp>
#include <TeeProcs.hpp>
#include <Series.hpp>
#include <ExtCtrls.hpp>
#include <Chart.hpp>
//---------------------------------------------------------------------------
class TChatForm : public TForm
{
__published:    // IDE-managed Components
        TButton *Button1;
        TPanel *Panel1;
        TEdit *Edit1;
        TLabel *Label1;
        TEdit *Edit2;
        TLabel *Label3;
        TChart *ch;
        TButton *Button2;
        TAreaSeries *Series1;
        TMemo *Memo1;
        void __fastcall RefreshChart(TObject *Sender);
        void __fastcall Button1Click(TObject *Sender);
        void __fastcall FormActivate(TObject *Sender);
        void __fastcall FormDeactivate(TObject *Sender);
private:        // User declarations
public:         // User declarations
        void __fastcall Prepare(void);
        __fastcall TChatForm(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TChatForm *Form1;
//---------------------------------------------------------------------------
#endif
 