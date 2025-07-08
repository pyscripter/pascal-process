program ProcessDemo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.Classes,
  PascalProcess in '..\Source\PascalProcess.pas';

procedure Test1;
// Simplest possible usage: Run a process and capture the output
var
  Output: TBytes;
begin
  {$IFDEF MSWINDOWS}
  Output := TPProcess.Execute('cmd /c echo Hi');
  {$ELSE}
  Output := TPProcess.Execute('echo Hi Ubuntu');
  {$ENDIF}
  Writeln(TEncoding.Default.GetString(Output));
end;

type
  TUtils = class
    class procedure OnRead(Sender: TObject; const Bytes: TBytes;
      BytesRead: Cardinal);
  end;

{ TUtils }

class procedure TUtils.OnRead(Sender: TObject; const Bytes: TBytes;
  BytesRead: Cardinal);
begin
  Writeln(TEncoding.Default.GetString(Bytes, 0, BytesRead));
end;

procedure Test2;
// Processes ouput as it gets produced
// The main thread terminates the process
var
  Process: IPProcess;
begin
  {$IFDEF MSWINDOWS}
  Process := TPProcess.Create('cmd /c dir c:\ /s');
  {$ELSE}
  Process := TPProcess.Create('ls -l -R /usr');
  {$ENDIF}
  Process.OnRead := TUtils.OnRead;
  WriteLn('Press Enter to start the process. Press Enter again to terminate');
  ReadLn;
  Process.Execute;
  ReadLn;
  Process.Terminate;
  Process.WaitFor;
  Writeln('Exit code: ' + Process.ExitCode.ToString);
end;

procedure Test3;
// Starting a GUI app
// This is just a test.  PascalProcess is not designed to start GUI apps.
// Use ShellExecute instead for that purpose.
var
  Process: IPProcess;
begin
  Process := TPProcess.Create('notepad.exe');
  Process.ShowWindow := swShowNormal;
  Process.Execute;
  // So that Process is not destroyed before executed
  while Process.State = TPPState.Created do
    TThread.Yield;
  Readln;
  Process.Terminate; // terminates the process but notepad remains open
  Writeln('Ended');
end;

begin
  try
    ReportMemoryLeaksOnShutdown := True;
    //Test1
    Test2;
    //Test3;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  Readln;
end.
