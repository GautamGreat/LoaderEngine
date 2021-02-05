unit Loader_Engine;

interface

{ 
  Loader Enigne by GautamGreat
  Note : All timeouts are in seconds.
  Coded just for fun
}

uses
  Winapi.Windows, System.SysUtils, Winapi.PsAPI, Winapi.TlHelp32;

type
  _PROCESS_BASIC_INFORMATION = packed record
    Reserved1 : PDWORD;
    PebBaseAddress : DWORD;
    Reserved2 : array[0..1] of PDWORD;
    UniqueProcessId : DWORD;
    Reserved3 : PDWORD;
  end;

type
  TLoaderEngine = class
    private
      hProcess, hThread : THandle;
      dwProcessID, dwThreadID : DWORD;
      StartupInfo : TStartupInfo;
      ProcessInfo : TProcessInformation;
      bProcessSuspended : Boolean;
    public
      constructor Create(sFilename : string; bCreateNew : Boolean; bSuspended : Boolean);
      function GetModuleBaseAddress : DWORD;
      procedure ReadMemory(Address : DWORD; var Buffer; Len : Integer);
      procedure WriteMemory(Address : DWORD; var Buffer; Len : Integer);
      function WaitTillBytes(Address : DWORD; Bytes : array of Byte; Timeout : Integer) : Boolean;
      function CheckIfSuspended : Boolean;
      function FindBytesPattern(ModuleName : string; Pattern, Mask : array of Byte; Hits : Integer) : DWORD;
      procedure SuspendPThread;
      procedure ResumePThread;
      procedure TerminateRemoteProcess;
      function GetProcessHandle : THandle;
      function GetThreadHandle : THandle;
      function WaitTillFirstWindow(Timeout : Integer) : Boolean;
      function GetRemoteDLLBase(DLLName : string) : DWORD;
      function AllocMemory(Size : NativeUInt) : Pointer;
      function DeAllocMemory(Memory : Pointer) : Boolean;
      destructor Destroy; override;
  end;

var
  ProcessID : DWORD;
  bEnumWindow : Boolean;

 { Some functions declaration which is not in Windows.pas}
function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: Boolean;
  dwThreadId: Cardinal): THandle; stdcall; external kernel32 name 'OpenThread';
function NtQueryInformationProcess(ProcessHandle: THANDLE; ProcessInformationClass: DWORD; ProcessInformation: Pointer;
  ProcessInformationLength: ULONG; ReturnLength: PULONG): LongInt; stdcall; external 'ntdll.dll';

implementation

{ This function return process id of given process name. If this function fail,
  It will return 0 as result. }
function DetectProcessID(sProcessName : string) : DWORD;
var
  bLoop : BOOL;
  ProcessEntry : TProcessEntry32;
  hSnapShot : THandle;
begin

  Result := 0;
  hSnapShot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  ProcessEntry.dwSize := SizeOf(TProcessEntry32);
  bLoop := Process32First(hSnapShot, ProcessEntry);

  while Integer(bLoop) <> 0 do
  begin
    if ProcessEntry.szExeFile = sProcessName then
    begin

      Result := ProcessEntry.th32ProcessID;
      Break;

    end;

    bLoop := Process32Next(hSnapShot, ProcessEntry);

  end;

end;

{ This function return main thread id of given process id of process. If this
  function failed, it will return 0 as result }
function DetectProocessThreadID(ProcessID : DWORD) : DWORD;
var
  bLoop : BOOL;
  ThreadEntry : TThreadEntry32;
  hSnapShot : THandle;
begin

  Result := 0;
  hSnapShot := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  ThreadEntry.dwSize := SizeOf(TThreadEntry32);
  bLoop := Thread32First(hSnapShot, ThreadEntry);

  while Integer(bLoop) <> 0 do
  begin

    if ThreadEntry.th32OwnerProcessID = ProcessID then
    begin

      Result := ThreadEntry.th32ThreadID;
      Break;

    end;

    bLoop := Thread32Next(hSnapShot, ThreadEntry);

  end;

end;

{ EnumWindows function for finding windows }
function EnumWindowsProc(HWND : THandle; lParam : LPARAM):Boolean; stdcall;
var
  procid : DWORD;
begin

  GetWindowThreadProcessId(HWND, procid);
  if procid = ProcessID then
  begin
    bEnumWindow := True;
    Result := False;         //we got it
  end
  else
  begin
    Result := True;        //return true for search again
  end;

end;

{ Constructor of Loader Engine. }
constructor TLoaderEngine.Create(sFilename: string; bCreateNew: Boolean; bSuspended : Boolean);
var
  dwCreationFlag : DWORD;
begin

  ZeroMemory(@StartupInfo, SizeOf(StartupInfo));
  ZeroMemory(@ProcessInfo, SizeOf(ProcessInfo));

  if bSuspended then
  begin
    bProcessSuspended := True;
    dwCreationFlag := CREATE_SUSPENDED;
  end
  else
  begin
    bProcessSuspended := False;
    dwCreationFlag := NORMAL_PRIORITY_CLASS;
  end;

  if bCreateNew then
  begin
    if CreateProcess(PChar(sFilename), nil, nil, nil, False, dwCreationFlag, nil, nil, StartupInfo, ProcessInfo) then
    begin

      hProcess := ProcessInfo.hProcess;
      hThread  := ProcessInfo.hThread;
      dwProcessID := ProcessInfo.dwProcessId;
      dwThreadID := ProcessInfo.dwThreadId;
      ProcessID := dwProcessID;
      bProcessSuspended := False;

    end
    else
    begin
      raise Exception.Create('Could not create process.');
    end;
  end
  else
  begin
    dwProcessID := DetectProcessID(ExtractFileName(sFilename));
    if dwProcessID <> 0 then
    begin

      hProcess := OpenProcess(PROCESS_ALL_ACCESS, False, dwProcessID);
      dwThreadID := DetectProocessThreadID(dwProcessID);
      if dwThreadID <> 0 then
      begin

        hThread := OpenThread(PROCESS_ALL_ACCESS, False, dwThreadID);
        if bSuspended then
        begin
          SuspendPThread;
        end;

      end
      else
      begin

        raise Exception.Create('Could not find thread id of Process.');

      end;

    end
    else
    begin

      raise Exception.Create('Could not find process.');

    end;

  end;

end;

{ This procedure is used for writing remote process memory. }
procedure TLoaderEngine.ReadMemory(Address : DWORD; var Buffer; Len : Integer);
var
  bytesread : NativeUInt;
begin
  ReadProcessMemory(hProcess, Pointer(Address), @Buffer, Len, bytesread);
end;

{ This procedure is used for writing memory. }
procedure TLoaderEngine.WriteMemory(Address: Cardinal; var Buffer; Len: Integer);
var
  bytesread : NativeUInt;
begin
  WriteProcessMemory(hProcess, Pointer(Address), @Buffer, Len, bytesread);
end;

{ This function returns module base of remote process. If this function fail,
  It returns 0 as result. }
function TLoaderEngine.GetModuleBaseAddress : DWORD;
var
  PBI  : _PROCESS_BASIC_INFORMATION;
begin

  NtQueryInformationProcess(hProcess, 0, @PBI, SizeOf(PBI), nil);
  ReadMemory(PBI.PebBaseAddress+8, Result, 4);

end;

{ This function will stop the program here, until it detect a bytes pattern or timeout. }
function TLoaderEngine.WaitTillBytes(Address : DWORD; Bytes : array of Byte; Timeout : Integer) : Boolean;
var
  ReadBuffer : array of Byte;
  TimeoutCounter : Integer;
begin
  TimeoutCounter := 0;

  SetLength(ReadBuffer, Length(Bytes));
  Result := False;
  while not Result do
  begin

    ReadMemory(Address, ReadBuffer[0], Length(ReadBuffer));
    if CompareMem(@ReadBuffer[0], @Bytes[0], Length(ReadBuffer)) then
    begin
      Result := True;
      Break;
    end;

    inc(TimeoutCounter);
    if TimeoutCounter div 100 = Timeout then
    begin
      Result := False;
      Break;

    end;

    Sleep(10);
  end;

end;

{ This function suspend  the remote thread }
procedure TLoaderEngine.SuspendPThread;
begin
  SuspendThread(hThread);
  bProcessSuspended := True;
end;

{ This function resume  the remote thread }
procedure TLoaderEngine.ResumePThread;
begin
  ResumeThread(hThread);
  bProcessSuspended := False;
end;

{ This function Exit the remote process }
procedure TLoaderEngine.TerminateRemoteProcess;
begin
  TerminateProcess(hProcess, 0);
end;

{ This function return the state of proces. If suspended it will return true }
function TLoaderEngine.CheckIfSuspended : Boolean;
begin
  Result := bProcessSuspended;
end;

{ This function returns the VA (Virtual Address) of desired dll or main process
  if you wanna find pattern in main process itself you have to put main exe name
  in ModuleName parameter, else you can put the name of dll }
function TLoaderEngine.FindBytesPattern(ModuleName : string; Pattern: array of Byte; Mask: array of Byte; Hits : Integer): DWORD;
var
  PELocation : DWORD;
  NoOfSections, PESign : Word;
  SectionHeader : IMAGE_SECTION_HEADER;
  BaseAddress, SectionStartAddress : DWORD;
  i, j, k, cnt: Integer;
  SectionDataBuffer : array of Byte;
begin
  PELocation := 0;
  NoOfSections := 0;
  PESign := 0;
  cnt := 0;
  Result := 0;
  ZeroMemory(@SectionHeader, SizeOf(SectionHeader));


  BaseAddress := GetRemoteDLLBase(ModuleName);
  ReadMemory(BaseAddress, PESign, 2);
  if PESign = $5A4D then
  begin

    ReadMemory(BaseAddress + $3C, PELocation, 4);
    ReadMemory(BaseAddress + PELocation, PESign, 2);

    if PESign = $4550 then
    begin

      ReadMemory(BaseAddress + PELocation + 6, NoOfSections, 2);
      if NoOfSections > 0 then
      begin

        SectionStartAddress := BaseAddress + PELocation + $F8;
        for i := 1 to NoOfSections do
        begin
          Result := 0;
          j := 0;

          { Read section header }
          ReadMemory(SectionStartAddress, SectionHeader, SizeOf(SectionHeader));
          { Set Length of array and read data from process }
          SetLength(SectionDataBuffer, SectionHeader.Misc.VirtualSize);
          ReadMemory(SectionHeader.VirtualAddress + BaseAddress, SectionDataBuffer[0], SectionHeader.Misc.VirtualSize);

          { Let's process that data }
          for k := 0 to (SectionHeader.Misc.VirtualSize - Length(Pattern)) -1 do
          begin
            if (SectionDataBuffer[k] = Pattern[j]) or (Mask[j] = 1) then
            begin
              Inc(j);
              if Length(Pattern) = j then
              begin
                Inc(cnt);
                { Check if we found it }
                if Hits = cnt then
                begin
                  Result := SectionHeader.VirtualAddress + (k - (Length(Pattern) - 1)) + BaseAddress;
                  Break;
                end;

              end;
            end
            else
              j := 0;
          end;

          if Result <> 0 then
            Break;

          { Process next section }
          SectionStartAddress := SectionStartAddress + SizeOf(IMAGE_SECTION_HEADER);

        end;

      end
      else
        Result := 0;

    end
    else
      Result := 0;

  end
  else
    Result := 0;

end;

{ This function return handle of process }
function TLoaderEngine.GetProcessHandle : THandle;
begin
  Result := hProcess;
end;

{ This function return handle of thread }
function TLoaderEngine.GetThreadHandle: THandle;
begin
  Result := hThread;
end;

{ This function will stop the program here until it finds a newly created window
  of Target or until it hits the timeout. }
function TLoaderEngine.WaitTillFirstWindow(Timeout: Integer) : Boolean;
var
  TimeoutCounter : Integer;
begin

  TimeoutCounter := 0;
  bEnumWindow := False;

  { Loop for checking EnumWindows }
  while not bEnumWindow do
  begin

    EnumWindows(@EnumWindowsProc, 0);

    Inc(TimeoutCounter);
    if TimeoutCounter div 100 = Timeout then
    begin
      Break;
    end;

  end;

  Result := bEnumWindow;

end;

{ This function return the base address of loaded dll in Remote process.
  If function fails returns 0 }
function TLoaderEngine.GetRemoteDLLBase(DLLName : string) : DWORD;
var
  cbNeeded, DLLPathSize : DWORD;
  DLLPath : string;
  hModP : PHMODULE;
  hMods : array of HMODULE;
  Filename : array[0..MAX_PATH-1] of Char;
  i : Integer;
begin

  EnumProcessModules(hProcess, nil, 0, cbNeeded);
  Result := 0;

  if cbNeeded <= 0 then Exit;

  //Alloc memory for storing hMods
  SetLength(hMods, cbNeeded div sizeof(HMODULE));
  ZeroMemory(@hMods[0], SizeOf(hMods));
  hModP := @hMods[0];

  if EnumProcessModules(hProcess, hModP, cbNeeded, cbNeeded) then
  begin

    for i := 0 to Length(hMods)-1 do
    begin

      ZeroMemory(@Filename[0], Length(Filename)*2);
      DLLPathSize := Length(Filename);
      if GetMappedFileName(hProcess, Pointer(hMods[i]), @Filename[0],DLLPathSize) > 0 then
      begin

        //do nothing

      end
      else
      begin     // just another trick to retrive dll path

        GetModuleFileNameEx(hProcess, hMods[i], @Filename[0], DLLPathSize);

      end;

      //make both text in lowercase just for case sensitive
      //if DLLname found in DLLpath break the loop and return Base of DLL
      DLLPath := LowerCase(Filename);
      DLLName := LowerCase(DLLName);
      if Pos(DLLName, DLLPath) > 0 then
      begin
        Result := hMods[i];
        Break;
      end;

    end;

  end
  else
    Result := 0;

end;

{ This function alloct memory in remote process, if this function fail it will return
 nil as result }
function TLoaderEngine.AllocMemory(Size: NativeUInt) : Pointer;
begin
  Result := VirtualAllocEx(hProcess, nil, Size, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
end;

{ This function free memory in which is alloct by AllocMemory }
function TLoaderEngine.DeAllocMemory(Memory: Pointer) : Boolean;
begin
  
  if VirtualFreeEx(hProcess, Memory, 0, MEM_RELEASE) then
    Result := True
  else
    Result := false;

end;

{ Destructor of TLoaderEngine class }
destructor TLoaderEngine.Destroy;
begin
  inherited;
  CloseHandle(hProcess);
  CloseHandle(hThread);
end;

end.
