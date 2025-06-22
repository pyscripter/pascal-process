program ProcessDemo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  PascalProcess in '..\Source\PascalProcess.pas';

procedure Test1;
var
  Process: IPProcess;
begin
  Process := TPProcess.Create('cmd /c echo Hi');
  Process.SyncExecute;
  Writeln(TEncoding.ANSI.GetString(Process.Output));
end;

type
  TUtils = class
    class procedure OnRead(Sender: TObject; const Bytes: TBytes);
  end;

{ TUtils }

class procedure TUtils.OnRead(Sender: TObject; const Bytes: TBytes);
begin
  Writeln(TEncoding.ANSI.GetString(Bytes));
end;

procedure Test2;
var
  Process: IPProcess;
begin
  Process := TPProcess.Create('cmd /c dir c:\ /s');
  WriteLn('Press Enter to start the process. Press Enter again to terminate');
  Process.OnRead := TUtils.OnRead;
  ReadLn;
  Process.Execute;
  ReadLn;
  Process.Terminate;
end;


begin
  try
    ReportMemoryLeaksOnShutdown := True;
    //Test1;
    Test2;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  Readln;
end.
