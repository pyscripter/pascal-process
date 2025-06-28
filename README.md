# pascal-process
Pascal library for running processes and redirecting their output.

## Introduction

There are other pascal components for running processess and redirect their output.   This library is the outcome of frustrations with most of those components:

- Fixation with and premature conversion to strings.  Processes produce and consume bytes.
- Blocking reading of process output, resulting to inefficiencies (tight loops with Sleep, or separate threads for reading the output or providing input to the process)
- Incomplete features and/or over-bloated

## Features
- Asynchronous reading of process output
- Separate stdout and stderr reading which can optionally be merged
- Ability to consume output as it is produced or else let it accumulate and read the final result
- Ability to provide input to the running process before or while the process is running.
- Ability to terminate the running process.
- Synchronous and asynchronous execution of processes.
- Interfaced-based facilitating memory management.

## Limitations
Currently the library is Windows only.  The intention is to support other platforms (help wanted).  

## Installation
You do not need to install the library. Just download or clone this repo and add the source subdirectory to the Library path.

## Usage
This is a single unit library.  Add PascalProcess to your uses clause.  

If you just want to get the output of a process you can use the class functions of TPProcess.

```pascal
  TPProcess = class(TInterfacedObject, IPProcess)
    class function Execute(const ACommandLine: string;
      const ACurrentDir: string = ''): TBytes; overload;
    class procedure Execute(const ACommandLine: string;
      const ACurrentDir: string; out Output, ErrOutput: TBytes) overload;
  end;
```

This is an example:

```pascal
var
  Output: TBytes;
begin
  Output := TPProcess.Execute('cmd /c echo Hi');
  Writeln(TEncoding.ANSI.GetString(Output));
end;
```

For more demanding cases you can use the IPProcess interface.

Example:

```pascal
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
// Processes ouput as it gets produced
// The main thread terminates the process
var
  Process: IPProcess;
begin
  Process := TPProcess.Create('cmd /c dir c:\ /s');
  Process.OnRead := TUtils.OnRead;
  WriteLn('Press Enter to start the process. Press Enter again to terminate');
  ReadLn;
  Process.Execute;
  ReadLn;
  Process.Terminate;
end;
```

Here follows the definition of IPProcess

```pascal
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
    swHide,
    swMaximize,
    swMinimize,
    swShow,
    swShowMinimized,
    swoshowMinNoActive,
    swShowNA,
    swShowNormal
  );

  TPPReadEvent = procedure(Sender: TObject; const Bytes: TBytes) of object;

  {$SCOPEDENUMS ON}
  TPPState = (Created, Running, Completed, Terminated, Exception);
  {$SCOPEDENUMS OFF}

  IPProcess = interface
  ['{02CBC80B-CCF2-410C-96BE-C7EBE88BD8A4}']
    // Procedures

    /// <summary> Writes the Bytes to the stdin of the process </summary>
    /// <remarks>
    ///   Can be used before or during the execution of the process
    /// </remarks>
    procedure WriteProcessInput(Bytes: TBytes);

    /// <summary> Executes the process asynchronously </summary>
    procedure Execute;

    /// <summary> Executes the process synchronously </summary>
    /// <remarks> If an exception occures it raises it </remarks>
    procedure SyncExecute;

    /// <summary> Terminates the running process </summary>
    procedure Terminate;

    /// <summary> Wait for the process to exit </summary>
    procedure WaitFor;

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
```