object MainForm: TMainForm
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu, biMinimize]
  Caption = 'zxcvbn-pascal Demo'
  ClientHeight = 400
  ClientWidth = 664
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    664
    400)
  PixelsPerInch = 96
  TextHeight = 13
  object labStrength: TLabel
    Left = 16
    Top = 59
    Width = 94
    Height = 13
    Caption = 'Password strength:'
  end
  object labWarnings: TLabel
    Left = 16
    Top = 92
    Width = 630
    Height = 300
    Anchors = [akLeft, akTop, akRight, akBottom]
    AutoSize = False
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Consolas'
    Font.Style = []
    ParentFont = False
    ShowAccelChar = False
    WordWrap = True
    ExplicitWidth = 410
    ExplicitHeight = 258
  end
  object pbStrength: TPaintBox
    Left = 116
    Top = 62
    Width = 130
    Height = 8
    OnPaint = pbStrengthPaint
  end
  object Label1: TLabel
    Left = 16
    Top = 8
    Width = 46
    Height = 13
    Caption = 'Password'
  end
  object Label2: TLabel
    Left = 296
    Top = 8
    Width = 60
    Height = 13
    Caption = 'Locale Name'
  end
  object edPassword: TComboBox
    Left = 16
    Top = 24
    Width = 265
    Height = 21
    TabOrder = 0
    Text = 'correct horse battery staple'
    Items.Strings = (
      'correct horse battery staple'
      'Compl3xity < Length!'
      'cLbTyv2t'
      'Tr0ub4dor&3'
      'Tr0ub4dour&3'
      'hunter2')
  end
  object cbLocaleName: TComboBox
    Left = 296
    Top = 24
    Width = 73
    Height = 21
    TabOrder = 1
    Text = 'en-US'
    Items.Strings = (
      'en-US'
      'fr-FR'
      'de-DE')
  end
end
