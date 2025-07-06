# pascal-process
Pascal library for running processes and redirecting their output.

## Introduction

There are other pascal components for running processess and redirect their output.   This library is the outcome of frustrations with most of those components:

- Fixation with and premature conversion to strings.  Processes produce and consume bytes.
- Blocking reading of process output, resulting to inefficiencies (tight loops with Sleep, or separate threads for reading the output or providing input to the process)
- Incomplete features and/or over-bloated

## Features
- Multi-platform support. Works with all desktop Delphi compilers (WINDOWS, LINUX, MACOS)
- Asynchronous reading of process output
- Separate stdout and stderr reading which can optionally be merged
- Ability to consume output as it is produced or else let it accumulate and read the final result
- Ability to provide input to the running process before or while the process is running.
- Ability to terminate the running process.
- Synchronous and asynchronous execution of processes.
- Interfaced-based facilitating memory management.

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

See [here](https://github.com/pyscripter/pascal-process/blob/6bd6fe78e07a32c98408ce1bebcdd475107037ce/Source/PascalProcess.pas#L52) the definition of IPProcess.
