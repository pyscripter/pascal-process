{-----------------------------------------------------------------------------
 Unit Name: PascalProcess
 Author:    PyScripter (https://github.com/pyscripter)
 Purpose:   Run a process and redirect (capture) its ouput
 License:   MIT
-----------------------------------------------------------------------------}

unit PascalProcess;

interface

uses
  System.SysUtils,
  System.SyncObjs,
  System.Classes;

type
  /// <summary> Custom process exception </summary>
  /// <remarks> All exceptions are converted to PPException </remarks>
  PPException = class(Exception);

  /// <summary> The different process priorities </summary>
  TPProcessPriority = (
    ppIdle,
    ppNormal,
    ppHigh,
    ppRealTime,
    ppBelowNormal,
    ppAboveNormal
  );

  /// <summary>
  /// Encapsulates different values for TStartupInfo.wShowWindow
  /// See https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
  /// </summary>
  TPPShowWindow = (
    swNotSet,
    swHide,
    swMaximize,
    swMinimize,
    swShow,
    swShowMinimized,
    swoshowMinNoActive,
    swShowNA,
    swShowNormal
  );

  /// <summary> Controls the base creation flag for CreateProcess </summary>
  TPPCreationFlag = (cfNoWindow, cfNewConsole);

  TPPReadEvent = procedure(Sender: TObject; const Bytes: TBytes; BytesRead: Cardinal) of object;

  {$SCOPEDENUMS ON}
  TPPState = (Created, Running, Completed, Terminated, Exception);
  {$SCOPEDENUMS OFF}

  IPProcess = interface
  ['{02CBC80B-CCF2-410C-96BE-C7EBE88BD8A4}']
    // property getters
    function GetExitCode: Cardinal;
    function GetException: PPException;
    function GetOutput: TBytes;
    function GetErrorOutput: TBytes;
    function GetCommandLine: string;
    function GetCreationFlag: TPPCreationFlag;
    function GetCurrentDir: string;
    function GetBufferSize: Cardinal;
    function GetEnvironment: TStrings;
    function GetMergeError: Boolean;
    function GetProcessPriority: TPProcessPriority;
    function GetShowWindow: TPPShowWindow;
    function GetState: TPPState;
    function GetProcessId: Cardinal;
    // property setters
    procedure SetCommandLine(const Value: string);
    procedure SetCreationFlag(const Value: TPPCreationFlag);
    procedure SetCurrentDir(const Value: string);
    procedure SetBufferSize(const Value: Cardinal);
    procedure SetEnvironment(const Value: TStrings);
    procedure SetMergeError(const Value: Boolean);
    procedure SetProcessPriority(const Value: TPProcessPriority);
    procedure SetShowWindow(const Value: TPPShowWindow);
    procedure SetOnRead(const Value: TPPReadEvent);
    procedure SetOnErrorRead(const Value: TPPReadEvent);
    procedure SetOnTerminate(const Value: TNotifyEvent);

    // Procedures

    /// <summary>
    ///   Closes the stdin handle, signalling the end of input
    ///   Useful when the process executes in pipe mode.
    /// </summary>
    procedure CloseStdInHandle;

    /// <summary> Executes the process asynchronously </summary>
    procedure Execute;

    /// <summary> Executes the process synchronously </summary>
    /// <remarks> If an exception occures it raises it </remarks>
    procedure SyncExecute;

    /// <summary>
    ///   Raises a keyboard interrupt in the running process
    /// </summary>
    procedure RaiseKeyboardInterrupt;

    /// <summary> Terminates the running process </summary>
    procedure Terminate;

    /// <summary> Wait for the process to exit </summary>
    /// <param name="Timeout">
    ///   Optional argument. Wait up to Timeout milliseconds
    /// </param>
    /// <returns> True if the process finishes within the Timeout </returns>
    function WaitFor(Timeout: Cardinal = INFINITE): Boolean;

    /// <summary> Writes the Bytes to the stdin of the process </summary>
    /// <remarks>
    ///   Can be used before or during the execution of the process
    /// </remarks>
    procedure WriteProcessInput(Bytes: TBytes);

    // Input properties

    /// <summary> The command line to be executed </summary>
    /// <remarks>
    ///   Unless the executable is on the system path, it should
    ///   include the the full path to the executable even if
    ///   CurrentDir is set.  It should also include any arguments.
    /// </remarks>
    property CommandLine: string read GetCommandLine write SetCommandLine;

    /// <summary> The current directory for the created process </summary>
    property CurrentDir: string read GetCurrentDir write SetCurrentDir;

    /// <summary> The reading buffer size - default $4000 </summary>
    property BufferSize: Cardinal read GetBufferSize write SetBufferSize;

    /// <summary>
    ///   If not empty, it should contain a custom environment
    ///   for the created process.
    /// </summary>
    property Environment: TStrings read GetEnvironment write SetEnvironment;

    /// <summary> If True the stderr output is merged with stdout </summary>
    property MergeError: Boolean read GetMergeError write SetMergeError;

    /// <summary> The process priority - default ppNormal</summary>
    property ProcessPriority: TPProcessPriority read GetProcessPriority
      write SetProcessPriority;

    /// <summary>
    ///   Determines the of TStartupInfo.wShowWindow - Default swHide
    /// </summary>
    property ShowWindow: TPPShowWindow read GetShowWindow write SetShowWindow;

    /// <summary> The base creation flag for CreateProcess </summary>
    /// <remarks>
    ///   In most cases wsNotSet combined with cfNoWindow would work well.
    ///   The base creation flag will be combined with the priority flag
    ///   and CREATE_UNICODE_ENVIRONMENT.
    /// </remarks>
    property CreationFlag: TPPCreationFlag read GetCreationFlag
      write SetCreationFlag;

    // Output properties

    /// <summary> The process exit code </summary>
    property ExitCode: Cardinal read GetExitCode;

    /// <summary> The process redirected output </summary>
    /// <remarks>
    ///   If you provide an OnRead event handler, it will handle the output
    ///   and Output will be empty.
    /// </remarks>
    property Output: TBytes read GetOutput;

    /// <summary>The process redirected error output </summary>
    /// <remarks>
    ///   If MergeError is True or if you provide an OnReadError event handler
    ///   then it will be empty
    /// </remarks>
    property ErrorOutput: TBytes read GetErrorOutput;

    /// <summary> A PPException if an error occured or nil otherwise </summary>
    /// <remarks>
    ///   If you get the exception you need to either raise it or destroy it
    /// </remarks>
    property Exception: PPException read GetException;
    // Events

    /// <summary> The process state (see TPPState) </summary>
    property State: TPPState read GetState;

    /// <summary> The process state (see TPPState) </summary>
    property ProcessID: Cardinal read GetProcessId;

    /// <summary> Event triggered when output is received </summary>
    /// <remarks>
    ///   It is executed inside the process thread. If MergeError is True
    ///   then it is also triggered when error output is received.
    /// </remarks>
    property OnRead: TPPReadEvent write SetOnRead;

    /// <summary>
    ///   Event triggered when error output is received if MergeError is False
    /// </summary>
    /// <remarks> It is executed inside the process thread </remarks>
    property OnErrorRead: TPPReadEvent write SetOnErrorRead;

    /// <summary>
    ///   Event triggered when the process terminates.
    ///   It is executed inside the Main thread using Synchronize.
    /// </summary>
    property OnTerminate: TNotifyEvent write SetOnTerminate;
  end;

  TPProcess = class(TInterfacedObject, IPProcess)
  private
    // Fields
    FExitCode: Cardinal;
    FOutput: TBytes;
    FErrorOutput: TBytes;
    FCommandLine: string;
    FCreationFlag: TPPCreationFlag;
    FCurrentDir: string;
    FBufferSize: Cardinal;
    FEnvironment: TStrings;
    FMergeError: Boolean;
    FProcessPriority: TPProcessPriority;
    FShowWindow: TPPShowWindow;
    FWriteBytes: TBytes;
    FWriteLock: TCriticalSection;
    FWriteEvent: TSimpleEvent;
    FExecThread: TThread;
    FException: PPException;
    FState: TPPState;

    FOnRead: TPPReadEvent;
    FOnErrorRead: TPPReadEvent;
    FOnTerminate: TNotifyEvent;

    // property getters
    function GetExitCode: Cardinal;
    function GetException: PPException;
    function GetOutput: TBytes;
    function GetErrorOutput: TBytes;
    function GetCommandLine: string;
    function GetCreationFlag: TPPCreationFlag;
    function GetCurrentDir: string;
    function GetBufferSize: Cardinal;
    function GetEnvironment: TStrings;
    function GetMergeError: Boolean;
    function GetProcessPriority: TPProcessPriority;
    function GetShowWindow: TPPShowWindow;
    function GetState: TPPState;
    function GetProcessId: Cardinal;
    // property setters
    procedure SetCommandLine(const Value: string);
    procedure SetCreationFlag(const Value: TPPCreationFlag);
    procedure SetCurrentDir(const Value: string);
    procedure SetBufferSize(const Value: Cardinal);
    procedure SetEnvironment(const Value: TStrings);
    procedure SetMergeError(const Value: Boolean);
    procedure SetProcessPriority(const Value: TPProcessPriority);
    procedure SetShowWindow(const Value: TPPShowWindow);
    procedure SetOnRead(const Value: TPPReadEvent);
    procedure SetOnErrorRead(const Value: TPPReadEvent);
    procedure SetOnTerminate(const Value: TNotifyEvent);
    // Procedures
    procedure CloseStdInHandle;
    procedure Execute; overload;
    procedure SyncExecute;
    procedure ThreadTerminated(Sender: TObject);
    procedure WriteProcessInput(Bytes: TBytes);
    procedure RaiseKeyboardInterrupt;
    procedure Terminate;
    function WaitFor(Timeout: Cardinal = INFINITE): Boolean;
  public
    constructor Create(const ACommandLine: string; const ACurrentDir: string = '');
    destructor Destroy; override;
    /// <summary>
    ///   Executes ACommandLine and returns the output.
    ///   stderr is merged with stdout.
    /// </summary>
    class function Execute(const ACommandLine: string;
      const ACurrentDir: string = ''): TBytes; overload;
    /// <summary> Executes ACommandLine. </summary>
    /// <param name="Ouput"> On exit contains the process output </param>
    /// <param name="ErrOuput"> On exit contains the process stderr output </param>
    /// <returns> The process Exit code </returns>
    class function Execute(const ACommandLine: string; const ACurrentDir: string;
      out Output, ErrOutput: TBytes): Integer overload;
  end;

const
  /// <summary> Exit code when the process is forcefully terminated </summary>
  FORCED_TERMINATION = $FE;

implementation

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  Winapi.TlHelp32,
  {$ELSE}
  System.Math,
  System.DateUtils,
  Posix.SysTypes,
  Posix.Fcntl,
  Posix.Unistd,
  Posix.Signal,
  Posix.Stdlib,
  Posix.Errno,
  Posix.SysSelect,
  Posix.SysTime,
  Posix.SysWait,
  {$ENDIF}
  System.Generics.Collections;

resourcestring
  rsEmptyEnvString = 'Environment strings cannot be empty';
  SWaitFor = 'WaitFor called before calling Execute';

{$REGION 'Support routines'}


{$IFDEF MSWINDOWS}
// Windows-specific helper functions

// Closes handle if valid and ensures it becomes zero
procedure SafeCloseHandle(var Handle: THandle);
begin
  if Handle <> 0 then
  begin
    CloseHandle(Handle);
    Handle := 0;
  end;
end;

// Ensures hReadPipe and hWritePipe are zero on failure
function SafeCreatePipe(var hReadPipe, hWritePipe: THandle;
  lpPipeAttributes: PSecurityAttributes; nSize: DWORD): BOOL;
begin
  Result := CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
  if not Result then
  begin
    hReadPipe := 0;
    hWritePipe := 0;
  end;
end;

// Ensures the target handle is zero on failure
function SafeDuplicateHandle(hSourceProcessHandle, hSourceHandle,
  hTargetProcessHandle: THandle; lpTargetHandle: PHandle; dwDesiredAccess: DWORD;
  bInheritHandle: BOOL; dwOptions: DWORD): BOOL;
begin
  Result := DuplicateHandle(hSourceProcessHandle, hSourceHandle,
    hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle,
    dwOptions);
  if not Result and Assigned(lpTargetHandle) then
    lpTargetHandle^ := 0;
end;

var
  AsyncPipeCounter: Integer = 0;

// Helper routine to create asynchronous pipes.  From Jcl JclSysUtils
// Ensures output pipes are zero on failure
function CreateAsyncPipe(var hReadPipe, hWritePipe: THandle;
  lpPipeAttributes: PSecurityAttributes; nSize: DWORD): BOOL;
var
  Error: DWORD;
  PipeReadHandle, PipeWriteHandle: THandle;
  PipeName: string;
begin
  Result := False;

  hReadPipe := 0;
  hWritePipe := 0;

  if nSize = 0 then
    nSize := 4096;

  // Unique name
  AtomicIncrement(AsyncPipeCounter);
  PipeName := Format('\\.\Pipe\AsyncAnonPipe.%.8x.%.8x.%.8x',
    [GetCurrentProcessId, GetCurrentThreadId, AsyncPipeCounter]);

  PipeReadHandle := CreateNamedPipe(PChar(PipeName), PIPE_ACCESS_INBOUND or FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE or PIPE_WAIT, 1, nSize, nSize, 120 * 1000, lpPipeAttributes);
  if PipeReadHandle = INVALID_HANDLE_VALUE then
    Exit;

  PipeWriteHandle := CreateFile(PChar(PipeName), GENERIC_WRITE, 0, lpPipeAttributes, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL {or FILE_FLAG_OVERLAPPED}, 0);
  if PipeWriteHandle = INVALID_HANDLE_VALUE then
  begin
    Error := GetLastError;
    CloseHandle(PipeReadHandle);
    SetLastError(Error);
    Exit;
  end;

  hReadPipe := PipeReadHandle;
  hWritePipe := PipeWriteHandle;

  Result := True;
end;


function TerminateProcessTree(ProcessHandle: THandle; ProcessID: DWORD): Boolean;

type
  TProcessArray = TArray<DWORD>;

  function GetChildProcesses(ParentID: DWORD): TProcessArray;
  var
    Snapshot: THandle;
    Entry: PROCESSENTRY32;
    ProcessList: TList<DWORD>;
  begin
    Result := [];
    Snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if Snapshot = INVALID_HANDLE_VALUE then Exit;

    try
      Entry.dwSize := SizeOf(Entry);
      if not Process32First(Snapshot, Entry) then Exit;

      // Create ProcessList only after successful snapshot and first process enumeration
      ProcessList := TList<DWORD>.Create;
      try
        // Collect direct child processes
        repeat
          if Entry.th32ParentProcessID = ParentID then
            ProcessList.Add(Entry.th32ProcessID);
        until not Process32Next(Snapshot, Entry);

        Result := ProcessList.ToArray;
      finally
        ProcessList.Free;
      end;
    finally
      CloseHandle(Snapshot);
    end;
  end;

var
  PIDs: TProcessArray;
  I: Integer;
  Handle: THandle;
begin
  Result := True;
  PIDs := GetChildProcesses(ProcessID);
  for I := High(PIDs) downto 0 do
  begin
    Handle := OpenProcess(PROCESS_TERMINATE, False, PIDs[I]);
    if Handle <> 0 then
    begin
      Result := TerminateProcess(Handle, FORCED_TERMINATION) and Result;
      CloseHandle(Handle);
    end
    else
      Result := False;
  end;
  // Now terminate the parent process
  Result := TerminateProcess(ProcessHandle, FORCED_TERMINATION) and Result;
end;

// From JclStrings
function StringsToMultiSz(var Dest: PChar; const Source: TStrings): PChar;
var
  I, TotalLength: Integer;
  P: PChar;
begin
  Assert((Source <> nil) and (Source.Count > 0), 'StringsToMultiSz');
  TotalLength := 1;
  for I := 0 to Source.Count - 1 do
    if Source[I] = '' then
      raise PPException.CreateRes(@rsEmptyEnvString)
    else
      Inc(TotalLength, StrLen(PChar(Source[I])) + 1);
  GetMem(Dest, TotalLength * SizeOf(Char));
  P := Dest;
  for I := 0 to Source.Count - 1 do
  begin
    P := StrECopy(P, PChar(Source[I]));
    Inc(P);
  end;
  P^ := #0;
  Result := Dest;
end;

{$ELSE}

procedure SafeCloseHandle(var Handle: Integer);
begin
  if Handle <> -1 then
  begin
    __close(Handle);
    Handle := -1;
  end;
end;

function CreatePipe(var ReadPipe, WritePipe: Integer): Boolean;
var
  PipeFD: array[0..1] of Integer;
begin
  Result := pipe(@PipeFD[0]) = 0;
  if Result then
  begin
    ReadPipe := PipeFD[0];
    WritePipe := PipeFD[1];
  end
  else
  begin
    ReadPipe := -1;
    WritePipe := -1;
  end;
end;

function StringsToEnvp(Strings: TStrings): PPAnsiChar;
var
  I: Integer;
  Bytes: TBytes;
  Envp: PPAnsiChar;
begin
  GetMem(Envp, (Strings.Count + 1) * SizeOf(PAnsiChar));
  {$POINTERMATH ON}
  for I := 0 to Strings.Count - 1 do
  begin
    Bytes := TEncoding.UTF8.GetBytes(Strings[I]);
    GetMem(Envp[I], Length(Bytes) + 1); // +1 for null terminator
    Move(Bytes[0], Envp[I]^, Length(Bytes));
    Envp[I][Length(Bytes)] := #0; // null-terminate
  end;

  Envp[Strings.Count] := nil; // null-terminate the array
  {$POINTERMATH OFF}

  Result := Envp;
end;


procedure FreeEnvp(Envp: PPAnsiChar; Count: Integer);
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    {$POINTERMATH ON}
    FreeMem(Envp[I]);
    {$POINTERMATH OFF}
  FreeMem(Envp);
end;

function ShellSplitCommandLine(const Cmd: string): TArray<string>;
var
  Arg: string;
  InQuotes: Boolean;
  QuoteChar: Char;
  I: Integer;
  C: Char;

  function NextChar: Char;
  begin
    if I < Length(Cmd) then
      Result := Cmd[I + 1]
    else
      Result := #0;
  end;

begin
  Result := [];
  Arg := '';
  InQuotes := False;
  QuoteChar := #0;
  I := 1;
  while I <= Length(Cmd) do
  begin
    C := Cmd[I];
    if not InQuotes and CharInSet(C, ['"', '''']) then
    begin
      InQuotes := True;
      QuoteChar := C;
    end
    else if InQuotes and (C = QuoteChar) then
    begin
      InQuotes := False;
      QuoteChar := #0;
    end
    else if (C = '\') and (I < Length(Cmd)) then
    begin
      Inc(I);
      Arg := Arg + Cmd[I];
    end
    else if not InQuotes and (C = ' ') then
    begin
      if Arg <> '' then
      begin
        Result := Result + [Arg];
        Arg := '';
      end;
    end
    else
      Arg := Arg + C;
    Inc(I);
  end;
  if Arg <> '' then
    Result := Result + [Arg];
end;

{$ENDIF}

{$REGION 'TProcessThread'}
type
  TProcessThread = class(TThread)
  private
    FProcess: TPProcess;
    {$IFDEF MSWINDOWS}
    FProcessInformation: TProcessInformation;
    {$ELSE}
    FProcessID: pid_t;
    {$ENDIF}
    FOutputStream: TBytesStream;
    FErrorOutputStream: TBytesStream;
    procedure ReadOutput(const Bytes: TBytes; BytesRead: Cardinal);
    procedure ReadErrorOutput(const Bytes: TBytes; BytesRead: Cardinal);
  protected
    procedure DoTerminate; override;
    procedure Execute; override;
    procedure TerminatedSet; override;
  public
    constructor Create(Process: TPProcess);
    destructor Destroy; override;
    procedure RaiseKeyboardInterrupt;
  end;


constructor TProcessThread.Create(Process: TPProcess);
begin
  inherited Create(False);
  FProcess := Process;

  FOutputStream := TBytesStream.Create;
  FErrorOutputStream := TBytesStream.Create;

  FreeOnTerminate := False;
end;

{$IFDEF MSWINDOWS}
type
  TOnReadProc = procedure(const Bytes: TBytes; BytesRead: Cardinal) of object;

  PExtOverlapped = ^TExtOverlapped;
  TExtOverlapped = record
    Overlapped: TOverlapped;
    Process: TPProcess;
    Buffer: TBytes;
    OnReadProc: TOnReadProc;
    PipeHandle: PHandle;
  end;

// Completion routine for ReadFileEx
procedure ReadCompletionRoutine(dwErrorCode: DWORD; dwNumberOfBytesTransfered: DWORD;
  lpOverlapped: POverlapped); stdcall;
begin
  // Check for errors or pipe closure
  if dwErrorCode <> 0 then
  begin
    SafeCloseHandle(PExtOverlapped(lpOverlapped).PipeHandle^);
    Exit;
  end;

  // Process received data
  if dwNumberOfBytesTransfered > 0 then
    PExtOverlapped(lpOverlapped).OnReadProc(PExtOverlapped(lpOverlapped).Buffer,
      dwNumberOfBytesTransfered);

  ZeroMemory(lpOverlapped, SizeOf(TOverlapped));

  // Issue another read
  if not ReadFileEx(
    PExtOverlapped(lpOverlapped).PipeHandle^,
    @PExtOverlapped(lpOverlapped).Buffer[0],
    Length(PExtOverlapped(lpOverlapped).Buffer),
    lpOverlapped,
    @ReadCompletionRoutine)
  then
    SafeCloseHandle(PExtOverlapped(lpOverlapped).PipeHandle^);
end;
{$ENDIF}

destructor TProcessThread.Destroy;
begin
  FOutputStream.Free;
  FErrorOutputStream.Free;
  inherited;
end;

procedure TProcessThread.DoTerminate;
begin
  FProcess.ThreadTerminated(Self);
end;

procedure TProcessThread.Execute;
{$IFDEF MSWINDOWS}
const
  ShowWindowValues: array [TPPShowWindow] of DWORD =
    (0, SW_HIDE, SW_MAXIMIZE, SW_MINIMIZE, SW_SHOW, SW_SHOWMINIMIZED,
     SW_SHOWMINNOACTIVE, SW_SHOWNA, SW_SHOWNORMAL);
  ProcessPriorities: array [TPProcessPriority] of DWORD =
    (IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
     REALTIME_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
     ABOVE_NORMAL_PRIORITY_CLASS);
  CreationFlags: array [TPPCreationFlag] of DWORD =
    (CREATE_NO_WINDOW, CREATE_NEW_CONSOLE);
var
  StartupInfo: TStartupInfo;
  SecurityAttributes: TSecurityAttributes;
  ReadHandle, WriteHandle: THandle;
  ErrorReadHandle, ErrorWriteHandle: THandle;
  StdInReadPipe, StdInWriteTmpPipe, StdInWritePipe: THandle;
  BytesWritten: DWORD;
  ExtOverlapped, ExtOverlappedError: TExtOverlapped;
  PCurrentDir: PChar;
  EnvironmentData: PChar;
  Flags: DWORD;
  InpLen: Cardinal;
  CloseStdIn: Boolean;
begin
  NameThreadForDebugging('TProcessThread');

  SecurityAttributes.nLength := sizeof(SECURITY_ATTRIBUTES);
  SecurityAttributes.lpSecurityDescriptor := nil;
  SecurityAttributes.bInheritHandle := True;

  StdInWritePipe := 0;
  ReadHandle := 0;
  WriteHandle := 0;
  try
  // Create pipe for writing
    if not SafeCreatePipe(StdInReadPipe, StdInWriteTmpPipe, @SecurityAttributes, 0) then
      RaiseLastOSError;

    try
      if not SafeDuplicateHandle(GetCurrentProcess, StdInWriteTmpPipe,
        GetCurrentProcess, @StdInWritePipe, 0, False, DUPLICATE_SAME_ACCESS)
      then
        RaiseLastOSError;
    finally
      SafeCloseHandle(StdInWriteTmpPipe);
    end;

    // Create async pipe for reading stdout
    if not CreateAsyncPipe(ReadHandle, WriteHandle, @SecurityAttributes, FProcess.FBufferSize) then
      RaiseLastOSError;

    // Create async pipe for reading stderror
    if not CreateAsyncPipe(ErrorReadHandle, ErrorWriteHandle, @SecurityAttributes, FProcess.FBufferSize) then
      RaiseLastOSError;
  except
    SafeCloseHandle(StdInReadPipe);
    SafeCloseHandle(StdInWritePipe);
    SafeCloseHandle(ReadHandle);
    SafeCloseHandle(WriteHandle);

    raise;
  end;

  ZeroMemory(@StartupInfo, SizeOf(TStartupInfo));
  with StartupInfo do
  begin
    cb := SizeOf(StartupInfo);
    dwFlags := STARTF_USESTDHANDLES;
    if FProcess.FShowWindow <> swNotSet then
    begin
      dwFlags := STARTF_USESHOWWINDOW or dwFlags;
      wShowWindow := ShowWindowValues[FProcess.FShowWindow];
    end;
    hStdInput := StdInReadPipe;
    hStdOutput := WriteHandle;
    hStdError :=  ErrorWriteHandle;
  end;

  // CurrentDir cannot point to an empty string;
  if FProcess.FCurrentDir = '' then
    PCurrentDir := nil
  else
    PCurrentDir := PChar(FProcess.FCurrentDir);

  if FProcess.FEnvironment.Count = 0 then
    EnvironmentData := nil
  else
    StringsToMultiSz(EnvironmentData, FProcess.FEnvironment);

  Flags := CreationFlags[FProcess.FCreationFlag] or
    ProcessPriorities[FProcess.FProcessPriority] or CREATE_UNICODE_ENVIRONMENT;

  try
    try
      // Create the process
      if not CreateProcess(nil, PChar(FProcess.FCommandline), nil, nil, True,
        Flags, EnvironmentData, PCurrentDir, StartupInfo, FProcessInformation)
      then
        RaiseLastOSError;
    finally
      // Close handles no longer needed ASAP
      SafeCloseHandle(WriteHandle);  // Has been duplicated by CreateProcess
      SafeCloseHandle(ErrorWriteHandle);  // Has been duplicated by CreateProcess
      SafeCloseHandle(StdInReadPipe); // Has been duplicated by CreateProcess
    end;
    SafeCloseHandle(FProcessInformation.hThread); // Not needed

    // Asynchronous read from stdout
    ExtOverlapped.Process := FProcess;
    SetLength(ExtOverlapped.Buffer, FProcess.FBufferSize);
    ExtOverlapped.PipeHandle := @ReadHandle;
    ExtOverlapped.OnReadProc := ReadOutput;
    ZeroMemory(@ExtOverlapped.Overlapped, SizeOf(TOverlapped));

    if not ReadFileEx(
      ReadHandle,
      @ExtOverlapped.Buffer[0],
      FProcess.FBufferSize,
      @ExtOverlapped.Overlapped,
      @ReadCompletionRoutine)
    then
      RaiseLastOSError;

    // Asynchronous read from stderror
    ExtOverlappedError.Process := FProcess;
    SetLength(ExtOverlappedError.Buffer, FProcess.FBufferSize);
    ExtOverlappedError.PipeHandle := @ErrorReadHandle;
    ExtOverlappedError.OnReadProc := ReadErrorOutput;
    ZeroMemory(@ExtOverlappedError.Overlapped, SizeOf(TOverlapped));

    if not ReadFileEx(
      ErrorReadHandle,
      @ExtOverlappedError.Buffer[0],
      FProcess.FBufferSize,
      @ExtOverlappedError.Overlapped,
      @ReadCompletionRoutine)
    then
      RaiseLastOSError;

    FProcess.FState := TPPState.Running;

    repeat
      // Alertable wait so the that read completion interrupts the wait
      case WaitForSingleObjectEx(FProcess.FWriteEvent.Handle, INFINITE, True) of
        WAIT_OBJECT_0:
          begin
            // Write data to the server
            FProcess.FWriteLock.Enter;
            try
              if not Terminated and (Length(FProcess.FWriteBytes) > 0) then
              begin
                InpLen := Length(FProcess.FWriteBytes);
                CloseStdIn := FProcess.FWriteBytes[InpLen - 1] = $04 {EOT};
                if CloseStdIn then
                  Dec(InpLen);

                if (InpLen > 0) and not
                  WriteFile(StdInWritePipe, FProcess.FWriteBytes[0], InpLen,
                  BytesWritten, nil)
                then
                begin
                  SafeCloseHandle(StdInWritePipe);
                  RaiseLastOSError;
                end;
                FProcess.FWriteBytes := [];

                if CloseStdIn then
                begin
                  SafeCloseHandle(StdInWritePipe);
                end;
              end;
            finally
              FProcess.FWriteLock.Leave;
            end;
          end;
          WAIT_IO_COMPLETION: Continue;
        else
          RaiseLastOSError;
      end;
    until (ReadHandle = 0) and (ErrorReadHandle = 0);

    // Wait for the process to terminate so that we get the correct exit code
    WaitForSingleObject(FProcessInformation.hProcess, INFINITE);
    GetExitCodeProcess(FProcessInformation.hProcess, FProcess.FExitCode);
  finally
    // Save the stdout and stderr ouput
    if FOutputStream.Size > 0 then
      FProcess.FOutput :=  Copy(FOutputStream.Bytes, 0,  FOutputStream.Size);
    if FErrorOutputStream.Size > 0 then
      FProcess.FErrorOutput :=
        Copy(FErrorOutputStream.Bytes, 0,  FErrorOutputStream.Size);

    if EnvironmentData <> nil then
      FreeMem(EnvironmentData);
    // Close process and other handles
    SafeCloseHandle(FProcessInformation.hProcess);
    SafeCloseHandle(StdInWritePipe);
    SafeCloseHandle(ReadHandle);
    SafeCloseHandle(ErrorReadHandle);
  end;
end;
{$ELSE}
var
  StdInPipe, StdOutPipe, StdErrPipe: array[0..1] of Integer;
  StdInWrite, StdOutRead, StdErrRead: Integer;
  Args: TArray<string>;
  Argv: PPAnsiChar;
  I: Integer;
  Env: PPAnsiChar;
  M: TMarshaller;
  Buffer: TBytes;
  FDSet: fd_set;
  Timeout: timeval;
  BytesRead: ssize_t;
  InpLen: Cardinal;
  CloseStdIn: Boolean;
  Status: Integer;
  MaxFD: Integer;
begin
  NameThreadForDebugging('TProcessThread');
  FProcess.FState := TPPState.Running;

  // Parse command line
  Args := ShellSplitCommandLine(FProcess.FCommandLine);
  GetMem(Argv, (Length(Args) + 1) * SizeOf(PAnsiChar));
  try
    {$POINTERMATH ON}
    for I := 0 to Length(Args) - 1 do
      Argv[I] := M.AsAnsi(Args[I], TEncoding.UTF8.CodePage).ToPointer;
    Argv[Length(Args)] := nil;
    {$POINTERMATH OFF}

    // Create pipes
    if not CreatePipe(StdInPipe[0], StdInPipe[1]) or
       not CreatePipe(StdOutPipe[0], StdOutPipe[1]) or
       not CreatePipe(StdErrPipe[0], StdErrPipe[1])
    then
      raise PPException.Create('Pipe creation failed');

    FProcessID := fork;
    if FProcessID = 0 then // Child process
    begin
      dup2(StdInPipe[0], STDIN_FILENO);
      dup2(StdOutPipe[1], STDOUT_FILENO);
      dup2(StdErrPipe[1], STDERR_FILENO);

      // Close unused pipe ends
      __close(StdInPipe[1]);
      __close(StdOutPipe[0]);
      __close(StdErrPipe[0]);

      if FProcess.FCurrentDir <> '' then
        __chdir(M.AsAnsi(FProcess.FCurrentDir, TEncoding.UTF8.CodePage).ToPointer);

      {$POINTERMATH ON}
      if FProcess.FEnvironment.Count > 0 then
      begin
        Env := StringsToEnvp(FProcess.FEnvironment);
        execve(Argv[0], Argv, Env);
        FreeEnvp(Env, FProcess.FEnvironment.Count);
      end
      else
        execvp(Argv[0], Argv);
      {$POINTERMATH OFF}

      _exit(errno); // If exec fails
    end
    else if FProcessID > 0 then // Parent process
    begin
      // Parent keeps write end of stdin, read end of stdout/stderr
      StdInWrite := StdInPipe[1];
      StdOutRead := StdOutPipe[0];
      StdErrRead := StdErrPipe[0];
      // Close unused ends
      __close(StdInPipe[0]);
      __close(StdOutPipe[1]);
      __close(StdErrPipe[1]);
      // Set non-blocking
      fcntl(StdOutRead, F_SETFL, O_NONBLOCK);
      if (StdErrRead <> -1) then
        fcntl(StdErrRead, F_SETFL, O_NONBLOCK);
    end
    else
      raise PPException.Create('fork failed');
  finally
    FreeMem(Argv);
  end;

  // Now the rest of your read/write loop as before...
  SetLength(Buffer, FProcess.FBufferSize);
  repeat
    __FD_ZERO(FDSet);
    MaxFD := -1;
    if StdOutRead <> -1 then
    begin
      __FD_SET(StdOutRead, FDSet);
      if StdOutRead > MaxFD then MaxFD := StdOutRead;
    end;
    if StdErrRead <> -1 then
    begin
      __FD_SET(StdErrRead, FDSet);
      if StdErrRead > MaxFD then MaxFD := StdErrRead;
    end;
    Timeout.tv_sec := 0;
    Timeout.tv_usec := 100000; // 100ms
    if (MaxFD >= 0) and (select(MaxFD + 1, @FDSet, nil, nil, @Timeout) > 0) then
    begin
      if (StdOutRead <> -1) and FD_ISSET(StdOutRead, FDSet) then
      begin
        BytesRead := __read(StdOutRead, @Buffer[0], FProcess.FBufferSize);
        if BytesRead > 0 then
          ReadOutput(Buffer, BytesRead)
        else if BytesRead = 0 then
        begin
          SafeCloseHandle(StdOutRead);
          StdOutRead := -1;
        end;
      end;
      if (StdErrRead <> -1) and FD_ISSET(StdErrRead, FDSet) then
      begin
        BytesRead := __read(StdErrRead, @Buffer[0], FProcess.FBufferSize);
        if BytesRead > 0 then
          ReadErrorOutput(Buffer, BytesRead)
        else if BytesRead = 0 then
        begin
          SafeCloseHandle(StdErrRead);
          StdErrRead := -1;
        end;
      end;
    end;
    FProcess.FWriteLock.Enter;
    try
      if not Terminated and (Length(FProcess.FWriteBytes) > 0) then
      begin
        InpLen := Length(FProcess.FWriteBytes);
        CloseStdIn := FProcess.FWriteBytes[InpLen - 1] = $04;
        if CloseStdIn then
          Dec(InpLen);
        if InpLen > 0 then
        begin
          if __write(StdInWrite, @FProcess.FWriteBytes[0], InpLen) < 0 then
          begin
            SafeCloseHandle(StdInWrite);
            RaiseLastOSError;
          end;
        end;
        FProcess.FWriteBytes := [];
        if CloseStdIn then
          SafeCloseHandle(StdInWrite);
        FProcess.FWriteEvent.SetEvent;
      end;
    finally
      FProcess.FWriteLock.Leave;
    end;
    if waitpid(FProcessID, @Status, WNOHANG) <> 0 then
    begin
      if WIFEXITED(Status) then
        FProcess.FExitCode := WEXITSTATUS(Status)
      else
        FProcess.FExitCode := FORCED_TERMINATION;
      Break;
    end;
    TThread.Yield;
  until (StdOutRead = -1) and (StdErrRead = -1);

  if FOutputStream.Size > 0 then
    FProcess.FOutput := Copy(FOutputStream.Bytes, 0, FOutputStream.Size);
  if FErrorOutputStream.Size > 0 then
    FProcess.FErrorOutput := Copy(FErrorOutputStream.Bytes, 0, FErrorOutputStream.Size);

  SafeCloseHandle(StdInWrite);
  SafeCloseHandle(StdOutRead);
  SafeCloseHandle(StdErrRead);
end;
{$ENDIF}

{$IFDEF MSWINDOWS}
function CtrlHandler(fdwCtrlType: DWORD): LongBool; stdcall;
begin
  Result := True;
end;
{$ENDIF}

procedure TProcessThread.RaiseKeyboardInterrupt;
begin
  if FProcess.FState = TPPState.Running then
  begin
    {$IFDEF MSWINDOWS}
    if AttachConsole(FProcessInformation.dwProcessId) and
      SetConsoleCtrlHandler(@CtrlHandler, True) then
    begin
      GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
      Sleep(100);
      SetConsoleCtrlHandler(@CtrlHandler, False);
      FreeConsole;
    end;
    {$ELSE}
    kill(FProcessID, SIGINT);
    {$ENDIF}
  end;
end;

procedure TProcessThread.ReadErrorOutput(const Bytes: TBytes; BytesRead: Cardinal);
begin
  if FProcess.FMergeError then
    ReadOutput(Bytes, BytesRead)
  else
  begin
    if Assigned(FProcess.FOnErrorRead) then
      FProcess.FOnErrorRead(FProcess, Bytes, BytesRead)
    else
      FErrorOutputStream.Write(Bytes, BytesRead);
  end;
end;

procedure TProcessThread.ReadOutput(const Bytes: TBytes; BytesRead: Cardinal);
begin
  if Assigned(FProcess.FOnRead) then
    FProcess.FOnRead(FProcess, Bytes, BytesRead)
  else
    FOutputStream.Write(Bytes, BytesRead);
end;

procedure TProcessThread.TerminatedSet;
begin
  {$IFDEF MSWINDOWS}
  if Started and not Finished and (FProcessInformation.hProcess <> 0) then
    TerminateProcessTree(FProcessInformation.hProcess, FProcessInformation.dwProcessId);
  {$ELSE}
  if Started and not Finished and (FProcessID <> 0) then
    kill(FProcessID, SIGTERM);
  {$ENDIF}
  inherited;
end;

{$ENDREGION 'TProcessThread'}

{$REGION 'TPProcess'}

procedure TPProcess.CloseStdInHandle;
// Signal EOT - The Execute method will detect it and close the stdin hadnle
begin
  WriteProcessInput([$04]); // EOT character
end;

constructor TPProcess.Create(const ACommandLine: string; const ACurrentDir:
    string = '');
begin
  inherited Create;
  FCommandLine := ACommandLine;
  FCurrentDir := ACurrentDir;
  // CreateProcess expects writable CommandLine and CurrentDir
  UniqueString(FCommandLine);
  UniqueString(FCurrentDir);

  FBufferSize := $4000;
  FShowWindow := swHide;
  FProcessPriority := ppNormal;

  FEnvironment := TStringList.Create;
  FWriteLock := TCriticalSection.Create;
  FWriteEvent := TSimpleEvent.Create(nil, False, False, '');
end;

destructor TPProcess.Destroy;
begin
  FEnvironment.Free;
  FWriteLock.Free;
  FWriteEvent.Free;
  FExecThread.Free;
  FException.Free;

  inherited;
end;

class function TPProcess.Execute(const ACommandLine: string; const ACurrentDir:
    string; out Output, ErrOutput: TBytes): Integer;
var
  Process: IPProcess;
begin
  Process := TPProcess.Create(ACommandLine, ACurrentDir);
  Process.SyncExecute;
  Output := Process.Output;
  ErrOutput := Process.ErrorOutput;
  Result := Process.ExitCode;
end;

class function TPProcess.Execute(const ACommandLine,
  ACurrentDir: string): TBytes;
var
  Process: IPProcess;
begin
  Process := TPProcess.Create(ACommandLine, ACurrentDir);
  Process.MergeError := True;
  Process.SyncExecute;
  Result := Process.Output;
end;

procedure TPProcess.Execute;
begin
  FExecThread := TProcessThread.Create(Self);
end;

function TPProcess.GetBufferSize: Cardinal;
begin
  Result := FBufferSize;
end;

function TPProcess.GetCommandLine: string;
begin
  Result := FCommandLine;
end;

function TPProcess.GetCreationFlag: TPPCreationFlag;
begin
  Result := FCreationFlag;
end;

function TPProcess.GetCurrentDir: string;
begin
  Result := FCurrentDir;
end;

function TPProcess.GetEnvironment: TStrings;
begin
  Result := FEnvironment;
end;

function TPProcess.GetErrorOutput: TBytes;
begin
  Result := FErrorOutput;
end;

function TPProcess.GetException: PPException;
begin
  Result := FException;
  FException := nil;
end;

function TPProcess.GetExitCode: Cardinal;
begin
  Result := FExitCode;
end;

function TPProcess.GetMergeError: Boolean;
begin
  Result := FMergeError;
end;

function TPProcess.GetOutput: TBytes;
begin
  Result := FOutput;
end;

function TPProcess.GetProcessId: Cardinal;
begin
  if Assigned(FExecThread) then
  {$IFDEF MSWINDOWS}
    Result := TProcessThread(FExecThread).FProcessInformation.dwProcessId
  {$ELSE}
    Result := Cardinal(TProcessThread(FExecThread).FProcessID)
  {$ENDIF}
  else
    Result := 0;
end;

function TPProcess.GetProcessPriority: TPProcessPriority;
begin
  Result := FProcessPriority;
end;

function TPProcess.GetShowWindow: TPPShowWindow;
begin
  Result := FShowWindow;
end;

function TPProcess.GetState: TPPState;
begin
  Result := FState;
end;

procedure TPProcess.RaiseKeyboardInterrupt;
begin
  if Assigned(FExecThread) then
    TProcessThread(FExecThread).RaiseKeyboardInterrupt;
end;

procedure TPProcess.SetBufferSize(const Value: Cardinal);
begin
  FBufferSize := Value;
end;

procedure TPProcess.SetCommandLine(const Value: string);
begin
  FCommandLine := Value;
end;

procedure TPProcess.SetCreationFlag(const Value: TPPCreationFlag);
begin
  FCreationFlag := Value;
end;

procedure TPProcess.SetCurrentDir(const Value: string);
begin
  FCurrentDir := Value;
end;

procedure TPProcess.SetEnvironment(const Value: TStrings);
begin
  FEnvironment.Assign(Value);
end;

procedure TPProcess.SetMergeError(const Value: Boolean);
begin
  FMergeError := Value;
end;

procedure TPProcess.SetOnErrorRead(const Value: TPPReadEvent);
begin
  FOnErrorRead := Value;
end;

procedure TPProcess.SetOnRead(const Value: TPPReadEvent);
begin
  FOnRead := Value;
end;

procedure TPProcess.SetOnTerminate(const Value: TNotifyEvent);
begin
  FOnTerminate := Value;
end;

procedure TPProcess.SetProcessPriority(const Value: TPProcessPriority);
begin
  FProcessPriority := Value;
end;

procedure TPProcess.SetShowWindow(const Value: TPPShowWindow);
begin
  FShowWindow := Value;
end;

procedure TPProcess.SyncExecute;
begin
  FExecThread := TProcessThread.Create(Self);
  FExecThread.WaitFor;
  FreeAndNil(FExecThread);
  if FState = TPPState.Exception then
    raise GetException;
end;

procedure TPProcess.Terminate;
begin
  if Assigned(FExecThread) and FExecThread.Started
    and not FExecThread.Finished
  then
    FExecThread.Terminate;
end;

procedure TPProcess.ThreadTerminated(Sender: TObject);
begin
  if FExecThread.FatalException is Exception then
  begin
    FException :=
      PPException.Create(Exception(FExecThread.FatalException).Message);
    FState := TPPState.Exception;
  end
  else
  begin
    if FExitCode = FORCED_TERMINATION then
      FState := TPPState.Terminated
    else
      FState := TPPState.Completed;
  end;

  if Assigned(FOnTerminate) then
    TThread.Synchronize(FExecThread,
      procedure
      begin
        FOnTerminate(Sender);
      end);
end;

function TPProcess.WaitFor(Timeout: Cardinal = INFINITE): Boolean;
{$IFDEF MSWINDOWS}
begin
  if not Assigned(FExecThread) then
    raise PPException.CreateRes(@SWaitFor);

  while FState = TPPState.Created do
    TThread.Yield;

  if (FState = TPPState.Running) and
    (TProcessThread(FExecThread).FProcessInformation.hProcess <> 0) then
  begin
    Result :=
      WaitForSingleObject(TProcessThread(FExecThread).FProcessInformation.hProcess,
      Timeout) = WAIT_OBJECT_0;
    if Result then
      // Wait also for the thread to exit
      FExecThread.WaitFor;
  end
  else
    Result := True;
end;
{$ELSE}
var
  StartTime: TDateTime;
  Status: Integer;
begin
  if not Assigned(FExecThread) then
    raise PPException.Create('WaitFor called before calling Execute');
  while FState = TPPState.Created do
    TThread.Yield;
  if FState = TPPState.Running then
  begin
    StartTime := Now;
    Result := False;
    repeat
      if waitpid(TProcessThread(FExecThread).FProcessID, @Status, WNOHANG) <> 0 then
      begin
        if WIFEXITED(Status) then
          FExitCode := WEXITSTATUS(Status)
        else
          FExitCode := FORCED_TERMINATION;
        Result := True;
        Break;
      end;
      TThread.Yield;
    until (Timeout <> INFINITE) and (MilliSecondsBetween(Now, StartTime) >= Timeout);
    if Result then
      FExecThread.WaitFor;
  end
  else
    Result := True;
end;
{$ENDIF}


procedure TPProcess.WriteProcessInput(Bytes: TBytes);
begin
  FWriteLock.Enter;
  try
    FWriteBytes := FWriteBytes + Bytes;
  finally
    FWriteLock.Leave;
  end;
  FWriteEvent.SetEvent;
end;

{$ENDREGION 'TPProcess'}

end.
