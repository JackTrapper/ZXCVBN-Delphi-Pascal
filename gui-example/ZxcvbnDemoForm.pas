unit ZxcvbnDemoForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, uDebouncedEvent, Vcl.ComCtrls,
  Zxcvbn;

type
  TMainForm = class(TForm)
    labStrength: TLabel;
    labWarnings: TLabel;
	 pbStrength: TPaintBox;
	 edPassword: TComboBox;
	 Label1: TLabel;
	 Label2: TLabel;
	 cbLocaleName: TComboBox;
	 procedure FormCreate(Sender: TObject);
	 procedure FormDestroy(Sender: TObject);
	 procedure pbStrengthPaint(Sender: TObject);
  private
	 { Private declarations }
	 FZxcvbn: TZxcvbn;
	 FPasswordScore: Integer;
  public
	 { Public declarations }
	 procedure DoOnPasswordEditChange(ASender: TObject);
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}
{$R Dictionaries.res}

const
	LOCALE_SNAME = $0000005c;  { locale name (ie: en-us) }

procedure TMainForm.FormCreate(Sender: TObject);
begin
	FZxcvbn := TZxcvbn.Create;

	FPasswordScore := 0;
	pbStrength.Canvas.Brush.Color := clWhite;
	pbStrength.Canvas.Pen.Color := clBlack;
	pbStrength.Canvas.Pen.Width := 1;

	cbLocaleName.Text := GetLocaleStr(LOCALE_USER_DEFAULT, LOCALE_SNAME, '');

	edPassword.OnChange := TDebouncedEvent.Wrap(DoOnPasswordEditChange, 200, Self);
	cbLocaleName.OnChange := TDebouncedEvent.Wrap(DoOnPasswordEditChange, 200, Self);

	DoOnPasswordEditChange(Sender);
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  FZxcvbn.Free;
end;

procedure TMainForm.pbStrengthPaint(Sender: TObject);
begin
  pbStrength.Canvas.Brush.Color := clWhite;
  pbStrength.Canvas.FillRect(Rect(0, 0, pbStrength.Width, pbStrength.Height));
  pbStrength.Canvas.Rectangle(0, 0, pbStrength.Width, pbStrength.Height);

  case FPasswordScore of
    0: begin pbStrength.Canvas.Brush.Color := $00241CED; pbStrength.Canvas.FillRect(Rect(1, 1, 1 * (pbStrength.Width div 12)-1, pbStrength.Height-1)); end;
    1: begin pbStrength.Canvas.Brush.Color := $00277FFF; pbStrength.Canvas.FillRect(Rect(1, 1, 2 * (pbStrength.Width div 5)-1, pbStrength.Height-1)); end;
    2: begin pbStrength.Canvas.Brush.Color := $000EC9FF; pbStrength.Canvas.FillRect(Rect(1, 1, 3 * (pbStrength.Width div 5)-1, pbStrength.Height-1)); end;
    3: begin pbStrength.Canvas.Brush.Color := $00E8A200; pbStrength.Canvas.FillRect(Rect(1, 1, 4 * (pbStrength.Width div 5)-1, pbStrength.Height-1)); end;
	 4: begin pbStrength.Canvas.Brush.Color := $004CB122; pbStrength.Canvas.FillRect(Rect(1, 1, pbStrength.Width-1, pbStrength.Height-1)); end;
  end;
end;

procedure TMainForm.DoOnPasswordEditChange(ASender: TObject);
var
	res: TZxcvbnResult;
	s: string;
	match: TZxcvbnMatch;
	dictionaryName: string;
begin
	FZxcvbn.LocaleName := cbLocaleName.Text;

  res := FZxcvbn.EvaluatePassword(edPassword.Text);
  try
		FPasswordScore := res.Score;
		pbStrength.Invalidate;

		s :=
				'Calculation runtime: '+Format('%.4f ms', [res.CalcTime])+#13#10+#13#10+

				'Score:               '+Format('%d / 4', [res.Score])+#13#10+
				'                     '+res.ScoreText+#13#10+#13#10+

				'Guesses (Log10):     '+FloatToStrF(res.GuessesLog10, ffFixed, 15, 5)+#13#10+#13#10+

				'Guess times: '+#13#10+
				' • 100 / hour:       '+res.CrackTimeOnlineThrottlingDisplay+' (throttling online attack)'+#13#10+
				' • 10  / second:     '+res.CrackTimeOnlineNoThrottlingDisplay+' (unthrottled online attack)'+#13#10+
				' • 10k / second:     '+res.CrackTimeOfflineSlowHashDisplay+' (offline attack, slow hash, many cores)'+#13#10+
				' • 10B / hour:       '+res.CrackTimeOfflineFastHashDisplay+' (offline attack, fast hash, many cores)';

		if res.WarningText <> '' then
		begin
			s := s+#13#10+#13#10+
					'Warning: ' + #10 +
					res.WarningText;
		end;

		if res.SuggestionsText <> '' then
		begin
			s := s+#13#10+#13#10+
					'Suggestions: ' + #10 +
					res.SuggestionsText;
		end;

		if res.MatchSequence.Count > 0 then
		begin
			s := s+#13#10+#13#10;
			for match in res.MatchSequence do
			begin
				dictionaryName := '';
				if match is TZxcvbnDictionaryMatch then
					dictionaryName := ' - '+TZxcvbnDictionaryMatch(match).DictionaryName;

				s := s+#13#10+
						'- "'+match.Token+'" ('+match.Pattern+dictionaryName+') - '+Format('%.5f bits', [match.Entropy]);
			end;
		end;

		labWarnings.Caption := s;
	finally
		res.Free;
	end;
end;

end.
