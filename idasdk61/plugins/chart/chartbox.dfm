object ChatForm: TChatForm
  Left = 761
  Top = 494
  ActiveControl = Button2
  AutoScroll = False
  Caption = 'Chart sample'
  ClientHeight = 376
  ClientWidth = 448
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnActivate = FormActivate
  OnDeactivate = FormDeactivate
  DesignSize = (
    448
    376)
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 320
    Top = 8
    Width = 76
    Height = 13
    Anchors = [akTop, akRight]
    Caption = '&Starting address'
    FocusControl = Edit1
  end
  object Label3: TLabel
    Left = 320
    Top = 56
    Width = 73
    Height = 13
    Anchors = [akTop, akRight]
    Caption = '&Ending address'
    FocusControl = Edit2
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 308
    Height = 376
    Align = alLeft
    Anchors = [akLeft, akTop, akRight, akBottom]
    Caption = 'Panel1'
    TabOrder = 1
    object ch: TChart
      Left = 1
      Top = 1
      Width = 306
      Height = 374
      AnimatedZoom = True
      BackWall.Brush.Color = clWhite
      BackWall.Brush.Style = bsClear
      Title.Text.Strings = (
        'Byte value distribution')
      BottomAxis.AxisValuesFormat = '##0.###'
      BottomAxis.LabelStyle = talText
      BottomAxis.RoundFirstLabel = False
      LeftAxis.Title.Caption = 'Byte values'
      Legend.Visible = False
      RightAxis.Visible = False
      TopAxis.Visible = False
      View3D = False
      Align = alClient
      TabOrder = 0
      object Series1: TAreaSeries
        Marks.ArrowLength = 8
        Marks.Style = smsValue
        Marks.Visible = False
        SeriesColor = clLime
        Title = 'Byte values'
        AreaLinesPen.Visible = False
        DrawArea = True
        Pointer.InflateMargins = True
        Pointer.Style = psRectangle
        Pointer.Visible = False
        XValues.DateTime = False
        XValues.Name = 'X'
        XValues.Multiplier = 1
        XValues.Order = loAscending
        YValues.DateTime = False
        YValues.Name = 'Y'
        YValues.Multiplier = 1
        YValues.Order = loNone
      end
    end
  end
  object Button1: TButton
    Left = 320
    Top = 144
    Width = 113
    Height = 25
    Anchors = [akTop, akRight]
    Cancel = True
    Caption = 'Close'
    ModalResult = 2
    TabOrder = 0
    OnClick = Button1Click
  end
  object Edit1: TEdit
    Left = 320
    Top = 24
    Width = 113
    Height = 21
    Anchors = [akTop, akRight]
    TabOrder = 2
  end
  object Edit2: TEdit
    Left = 320
    Top = 72
    Width = 113
    Height = 21
    Anchors = [akTop, akRight]
    TabOrder = 3
  end
  object Button2: TButton
    Left = 320
    Top = 104
    Width = 113
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'Refresh'
    Default = True
    TabOrder = 4
    OnClick = RefreshChart
  end
  object Memo1: TMemo
    Left = 312
    Top = 176
    Width = 129
    Height = 193
    Anchors = [akTop, akRight]
    Color = clBtnFace
    Lines.Strings = (
      'This is a sample plugin '
      'which demonstrates how '
      'to use Borland CBuilder '
      'and components to write '
      'IDA Pro plugins.'
      ''
      'You may enter the starting '
      'and ending addresses for '
      'the area of the interest or '
      'you may select the area in '
      'the disassembly and '
      'invoke this plugin.'
      '')
    ReadOnly = True
    TabOrder = 5
  end
end
