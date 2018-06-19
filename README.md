# LoaderEngine
An pascal based process patcher, that we call LoaderEngine
      constructor Create(Filename : string; NewProcess : Boolean);   //Create class with filename and a boolean switch for creating new process or open existing process
      function GetProcessInformation : Boolean;  //This function Create a new process or Open a created process
      function SuspendProcessThread : Boolean;  //This function will suspend thread
      function ResumeProcessThread : Boolean;  //This function will resume suspended thread
      function CheckProcessThreadStatus : TThreadStatus;  //This function will return thread status [ suspended or running ]
      function TerminateTarget : Boolean;  // this function will terminate process
      function FindFirstWindow(Timeout : Integer) : Boolean; //This function will wait untill it detects a window of created process
      function WaitTillByte(Address : DWORD; Buffer : array of Byte; Timeout : Integer) : Boolean; //This function will wait untill it find desired bytes in memory
      function WriteTargetProcessMemory(Address : DWORD; Buffer : array of Byte) : Boolean; // this function write memory of desired location
      function ReadTargetProcessMemory(Address : DWORD; Len : Integer; var Buffer) : Boolean; // this function read memory of desired location
      function GetModuleBaseAddress : DWORD; //this function returns base address of process
