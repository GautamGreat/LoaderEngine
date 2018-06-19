unit LoaderEngine;

interface

uses
  Winapi.Windows, Winapi.Messages, Winapi.TlHelp32;

type
  TThreadStatus = (Normal=1, Suspended);

  TF = packed record
  TEST        : DWORD;
  BaseAddress : DWORD;
  dd          : array[0..3] of DWORD;
  end;


type
  TLoaderEngine = class
    private
      SI : TStartupInfo;
      PI : TProcessInformation;
      stFilename : string;
      bCreateProcess : Boolean;
      hProcess, hThread : THandle;
      IsSuspended : Boolean;
    public
      constructor Create(Filename : string; NewProcess : Boolean);
      function GetProcessInformation : Boolean;
      function SuspendProcessThread : Boolean;
      function ResumeProcessThread : Boolean;
      function CheckProcessThreadStatus : TThreadStatus;
      function TerminateTarget : Boolean;
      function FindFirstWindow(Timeout : Integer) : Boolean;
      function WaitTillByte(Address : DWORD; Buffer : array of Byte; Timeout : Integer) : Boolean;
      function WriteTargetProcessMemory(Address : DWORD; Buffer : array of Byte) : Boolean;
      function ReadTargetProcessMemory(Address : DWORD; Len : Integer; var Buffer) : Boolean;
      function GetModuleBaseAddress : DWORD;
      destructor Destroy;
  end;

var
  EnumWindowBoolean : Boolean;
  processid, threadid : THandle;

function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: Boolean;
  dwThreadId: Cardinal): THandle; stdcall; external kernel32 name 'OpenThread';
function NtQueryInformationProcess(ProcessHandle: THANDLE; ProcessInformationClass: DWORD; ProcessInformation: Pointer;
  ProcessInformationLength: ULONG; ReturnLength: PULONG): LongInt; stdcall; external 'ntdll.dll';


implementation

function GetProcessId(ProcessName : string) : THandle;
var
  ProcessEntry : PROCESSENTRY32;
  ContinueLoop : LongBool;
  SnapShot : THandle;
begin
  SnapShot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  ProcessEntry.dwSize := Sizeof(ProcessEntry);
  ContinueLoop := Process32First(SnapShot, ProcessEntry);
  Result := 0;
  while Integer(ContinueLoop) <> 0 do
  begin
    if ProcessEntry.szExeFile = ProcessName then
    begin
      Result := ProcessEntry.th32ProcessID;
      Break;
    end;
    ContinueLoop := Process32Next(SnapShot, ProcessEntry);
  end;
end;

function GetThreadId(ProcessId : DWORD) : THandle;
var
  ThreadEntry : THREADENTRY32;
  ContinueLoop : LongBool;
  SnapShot : THandle;
begin
  SnapShot := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  ThreadEntry.dwSize := SizeOf(ThreadEntry);
  ContinueLoop := Thread32First(SnapShot, ThreadEntry);
  Result := 0;
  while Integer(ContinueLoop) <> 0 do
  begin
    if ThreadEntry.th32OwnerProcessID = ProcessId then
    begin
      Result := ThreadEntry.th32ThreadID;
      Break;
    end;
    ContinueLoop := Thread32Next(SnapShot, ThreadEntry);
  end;
end;

constructor TLoaderEngine.Create(Filename: string; NewProcess: Boolean);
begin
  stFilename := Filename;
  bCreateProcess := NewProcess;
  ZeroMemory(@SI, SizeOf(SI));
  ZeroMemory(@PI, SizeOf(PI));
  EnumWindowBoolean := False;
end;

function TLoaderEngine.GetProcessInformation : Boolean;
begin
  if bCreateProcess then
  begin
    if CreateProcess(PChar(stFilename), nil, nil, nil, False, NORMAL_PRIORITY_CLASS, nil, nil, SI, PI) then
    begin
      Result := True;
      hProcess := PI.hProcess;
      hThread := PI.hThread;
      processid := PI.dwProcessId;
      threadid := PI.dwThreadId;
      IsSuspended := False;
    end
    else
    begin
      Result := False;
    end;
  end
  else
  begin
    processid := GetProcessId(stFilename);
    if processid <> 0 then
    begin
      hProcess := OpenProcess(PROCESS_ALL_ACCESS, False, processid);
      threadid := GetThreadId(processid);
      if threadid <> 0 then
      begin
        Result := True;
        hThread := OpenThread(PROCESS_ALL_ACCESS, False, threadid);
        IsSuspended := False;
      end
      else
      begin
        Result := False;
      end;
    end
    else
    begin
      Result := False;
    end;
  end;
end;

function TLoaderEngine.SuspendProcessThread : Boolean;
begin
  if SuspendThread(hThread) <> -1 then
  begin
    Result := True;
  end
  else
  begin
    Result := False;
  end;
end;

function TLoaderEngine.ResumeProcessThread : Boolean;
begin
  if ResumeThread(hThread) <> -1 then
  begin
    Result := True;
  end
  else
  begin
    Result := False;
  end;
end;

function TLoaderEngine.CheckProcessThreadStatus : TThreadStatus;
begin
  if IsSuspended then
    Result := Suspended
  else
    Result := Normal;
end;

function TLoaderEngine.TerminateTarget : Boolean;
begin
  Result := TerminateProcess(hProcess, 0);
end;

function EnumWindowsProc(HWND : HWND; lParam : LPARAM) : Boolean; stdcall;
var
  oldhwnd : Cardinal;
begin
  GetWindowThreadProcessId(HWND, oldhwnd);
  if oldhwnd = processid then
  begin
    EnumWindowBoolean := True;
    Result := False;
  end
  else
  begin
    Result := True;
  end;
end;

function TLoaderEngine.FindFirstWindow(Timeout: Integer) : Boolean;
var
  Counter : Integer;
begin
  Counter := 0;
  while not EnumWindowBoolean do
  begin
    EnumWindows(@EnumWindowsProc, 0);
    Sleep(10);
    Inc(Counter);
    if Counter div 100 = Timeout then
    begin
      Result := False;
      Break;
    end;
  end;

  Result := EnumWindowBoolean;

end;

function TLoaderEngine.WaitTillByte(Address: Cardinal; Buffer: array of Byte; Timeout: Integer) : Boolean;
var
  BufferSize, i, Counter, TimeoutCounter : Integer;
  Loop : Boolean;
  BytesRead : NativeUInt;
  ReadBuffer : array of Byte;
begin
  Loop := False;
  TimeoutCounter := 0;
  Counter := 0;
  BufferSize := Length(Buffer);
  SetLength(ReadBuffer, BufferSize);

  while not Loop do
  begin
    ReadProcessMemory(hProcess, Pointer(Address), @ReadBuffer[0], BufferSize, BytesRead);
    for i := 0 to BufferSize - 1 do
    begin
      if ReadBuffer[i] = Buffer[i] then
        Inc(Counter)
      else
      begin
        Counter := 0;
        Break;
      end;

      if Counter = BufferSize then
      begin
        Loop := True;
        Break;
      end;

    end;

    Inc(TimeoutCounter);

    if TimeoutCounter div 100 = Timeout then
    begin
      Loop := False;
      Break;
    end;

    Sleep(10);

  end;

  Result := Loop;

end;

function TLoaderEngine.WriteTargetProcessMemory(Address: Cardinal; Buffer: array of Byte) : Boolean;
var
  BytesRead : NativeUInt;
begin
  Result := WriteProcessMemory(hProcess, Pointer(Address), @BUffer[0], Length(Buffer), BytesRead);
end;

function TLoaderEngine.ReadTargetProcessMemory(Address: Cardinal; Len: Integer; var Buffer) : Boolean;
var
  BytesRead : NativeUInt;
begin
  Result := ReadProcessMemory(hProcess, Pointer(Address), @Buffer, Len, BytesRead);
end;

function TLoaderEngine.GetModuleBaseAddress : DWORD;
var
  bytesread : NativeUInt;
  Files     : TF;
begin
  NtQueryInformationProcess(hProcess, 0, @Files, $18, nil);
  ReadProcessMemory(hProcess, Pointer(Files.BaseAddress+$8), @Result, 4, bytesread);
end;

destructor TLoaderEngine.Destroy;
begin
  stFilename := '';
  processid := 0;
  threadid := 0;
end;

end.
