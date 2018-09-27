program ZxcvbnDemo;







{$R 'Dictionaries.res' '..\dict\Dictionaries.rc'}

uses
  Vcl.Forms,
  ZxcvbnDemoForm in 'ZxcvbnDemoForm.pas' {MainForm},
  Zxcvbn in '..\src\Zxcvbn.pas',
  Zxcvbn_Dictionaries in '..\src\Zxcvbn_Dictionaries.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
