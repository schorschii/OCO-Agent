; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "OCO Agent"
#define MyAppVersion "1.1.6"
#define MyAppPublisher "Sieber Systems"
#define MyAppURL "https://github.com/schorschii/OCO-Agent"
#define MyAppSupportURL "https://sieber.systems/"
#define MyAppDir "C:\Program Files\OCO Agent"
#define AgentConfigFileName "oco-agent.ini"
#define AgentConfigFilePath MyAppDir+"\"+AgentConfigFileName
#define AgentApiEndpoint "/api-agent.php"
#define ServiceName "oco-agent"

[Setup]
AppId={{7427E511-277A-45DC-B017-805A7F2FAB0F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppSupportURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
WizardImageFile="installer-side-img.bmp"
WizardSmallImageFile="installer-top-img.bmp"
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon="{#MyAppDir}\oco-agent.exe,0"
DefaultDirName={code:GetDefaultDirName}
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
; Uncomment the following line to run in non administrative install mode (install for current user only.)
;PrivilegesRequired=lowest
OutputDir=".\"
OutputBaseFilename=oco-agent
CloseApplications=no
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"; LicenseFile: "..\..\LICENSE.txt"
; Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Files]
Source: "..\..\dist\oco-agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "..\..\oco-agent.dist.ini"; DestDir: "{app}"; DestName: "oco-agent.ini"; Flags: ignoreversion onlyifdoesntexist
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Dirs]
Name: {app}\service-checks

[UninstallDelete]
Type: filesandordirs; Name: "{#MyAppDir}"
Type: filesandordirs; Name: "{#MyAppDir}.old"
Type: filesandordirs; Name: "{#MyAppDir}.new"

[Code]
#ifdef UNICODE
  #define AW "W"
#else
  #define AW "A"
#endif

const
  SC_MANAGER_CONNECT = $0001;

  SERVICE_QUERY_STATUS = $0004;

  SERVICE_STOPPED = $00000001;
  SERVICE_START_PENDING = $00000002;
  SERVICE_STOP_PENDING = $00000003;
  SERVICE_RUNNING = $00000004;
  SERVICE_CONTINUE_PENDING = $00000005;
  SERVICE_PAUSE_PENDING = $00000006;
  SERVICE_PAUSED = $00000007;

type
  TSCHandle = THandle;

  TServiceStatus = record
    dwServiceType: DWORD;
    dwCurrentState: DWORD;
    dwControlsAccepted: DWORD;
    dwWin32ExitCode: DWORD;
    dwServiceSpecificExitCode: DWORD;
    dwCheckPoint: DWORD;
    dwWaitHint: DWORD;
  end;

var
  CustomQueryPage: TInputQueryWizardPage;
  ResultCode: Integer;
  InstallService: bool;
  DoNotStartService: bool;
  RestartService: bool;

function OpenService(hSCManager: TSCHandle; lpServiceName: string;
  dwDesiredAccess: DWORD): TSCHandle;
  external 'OpenService{#AW}@advapi32.dll stdcall';
function OpenSCManager(lpMachineName: string; lpDatabaseName: string;
  dwDesiredAccess: DWORD): TSCHandle;
  external 'OpenSCManager{#AW}@advapi32.dll stdcall';
function QueryServiceStatus(hService: TSCHandle;
  out lpServiceStatus: TServiceStatus): BOOL;
  external 'QueryServiceStatus@advapi32.dll stdcall';
function CloseServiceHandle(hSCObject: TSCHandle): BOOL;
  external 'CloseServiceHandle@advapi32.dll stdcall';

function GetServiceState(const SvcName: string): DWORD;
var
  Status: TServiceStatus;
  Manager: TSCHandle;
  Service: TSCHandle;
begin
  // open service manager with the lowest required access rights for this task
  Manager := OpenSCManager('', '', SC_MANAGER_CONNECT);
  if Manager <> 0 then
  try
    // open service with the only required access right needed for this task
    Service := OpenService(Manager, SvcName, SERVICE_QUERY_STATUS);
    if Service <> 0 then
    try
      // and query service status
      if QueryServiceStatus(Service, Status) then
        Result := Status.dwCurrentState
      else
        RaiseException('QueryServiceStatus failed. ' + SysErrorMessage(DLLGetLastError));
    finally
      CloseServiceHandle(Service);
    end
    else
      Result := SERVICE_STOPPED;
      //RaiseException('OpenService failed. ' + SysErrorMessage(DLLGetLastError));
  finally
    CloseServiceHandle(Manager);
  end
  else
    RaiseException('OpenSCManager failed. ' + SysErrorMessage(DLLGetLastError));
end;

function FileReplaceString(const FileName, SearchString, ReplaceString: string):boolean;
var
  MyFile : TStrings;
  MyText : string;
begin
  MyFile := TStringList.Create;
  try
    result := true;
    try
      MyFile.LoadFromFile(FileName);
      MyText := MyFile.Text;
      if StringChangeEx(MyText, SearchString, ReplaceString, True) > 0 then
      begin;
        MyFile.Text := MyText;
        MyFile.SaveToFile(FileName);
      end;
    except
      result := false;
    end;
  finally
    MyFile.Free;
  end;
end;

procedure InitializeWizard();
var
  InfFile: string;
  DefaultServerName: string;
  DefaultAgentKey: string;
begin
  { do not register the service again if this is an update }
  InstallService := not FileExists('{#MyAppDir}\oco-agent.exe');

  { ask for configuration values if no config file is present }
  if not FileExists('{#AgentConfigFilePath}') then
  begin
    CustomQueryPage := CreateInputQueryPage(  
      wpLicense,
      'Agent Configuration',
      'Please enter your OCO server details',
      'You can change these values later by directly editing the config file "oco-agent.ini"'
    );
    CustomQueryPage.Add('DNS name (FQDN) of your OCO server: ', False);
    CustomQueryPage.Add('Agent key to authenticate against your OCO server: ', False);

    { load defaults from .ini if given }
    DefaultServerName := ''
    DefaultAgentKey   := ''
    InfFile := ExpandConstant('{param:LOADINF}');
    if InfFile <> '' then
    begin
      DefaultServerName := GetIniString('Setup', 'ServerName', DefaultServerName, InfFile)
      DefaultAgentKey   := GetIniString('Setup', 'AgentKey', DefaultAgentKey, InfFile)
      DoNotStartService := GetIniBool('Setup', 'DoNotStartService', false, InfFile)
    end;
    CustomQueryPage.Values[0] := DefaultServerName
    CustomQueryPage.Values[1] := DefaultAgentKey
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    UninstallProgressForm.StatusLabel.Caption := 'Stopping and removing service...'
    Exec(ExpandConstant('{#MyAppDir}\service-wrapper.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{#MyAppDir}\service-wrapper.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000); { without this delay, windows screams that files are still in use }
    UninstallProgressForm.StatusLabel.Caption := 'Removing files...'
  end;
end;

function GetDefaultDirName(Param: string): string;
begin
  if GetServiceState(ExpandConstant('{#ServiceName}')) <> SERVICE_STOPPED then
    Result := ExpandConstant('{#MyAppDir}.new\')
  else
    Result := ExpandConstant('{#MyAppDir}\');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ServerName: string;
  app: string;
begin
  if CurStep = ssInstall then
  begin
    try
      { agent update: if service is running, install into dedicated .new directory and schedule restart because files of a running program can not be removed }
      if GetServiceState(ExpandConstant('{#ServiceName}')) <> SERVICE_STOPPED then
      begin
        RestartService := true;
        { delete previous .new directory }
        if DirExists(ExpandConstant('{#MyAppDir}.new\')) then
        begin
          DelTree(ExpandConstant('{#MyAppDir}.new\'), True, True, True)
        end;
      end;
    except
      //MsgBox(GetExceptionMessage, mbError, MB_OK);
    end;
  end;

  { postinstall: replace placeholders in config file, deny user access }
  if CurStep = ssPostInstall then
  begin
    WizardForm.StatusLabel.Caption := 'Writing agent config file...'
    if not (CustomQueryPage = nil) then
    begin
      if CustomQueryPage.Values[0] <> '' then
      begin
        ServerName := 'https://'+CustomQueryPage.Values[0]+'{#AgentApiEndpoint}'
      end;
      FileReplaceString(ExpandConstant('{#AgentConfigFilePath}'), 'SERVERURL', ServerName);
      FileReplaceString(ExpandConstant('{#AgentConfigFilePath}'), 'AGENTKEY', CustomQueryPage.Values[1]);
    end;

    if RestartService then
    begin
      { migrate config file }
      if FileExists(ExpandConstant('{#MyAppDir}\{#AgentConfigFileName}')) then
      begin
        FileCopy(ExpandConstant('{#MyAppDir}\{#AgentConfigFileName}'), ExpandConstant('{#MyAppDir}.new\{#AgentConfigFileName}'), False)
      end;
      { migrate service checks }
      if DirExists(ExpandConstant('{#MyAppDir}\service-checks')) then
      begin
        Exec('xcopy', ExpandConstant('"{#MyAppDir}\service-checks\*" "{#MyAppDir}.new\service-checks"'), '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
      end;
      { hack: ensure that InnoSetup install path point sto normal directory, not .new }
      RegWriteStringValue(HKEY_LOCAL_MACHINE, ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1'), 'QuietUninstallString', '"{#MyAppDir}\unins000.exe" /SILENT');
      RegWriteStringValue(HKEY_LOCAL_MACHINE, ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1'), 'UninstallString', '"{#MyAppDir}\unins000.exe"');
      RegWriteStringValue(HKEY_LOCAL_MACHINE, ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1'), 'InstallLocation', '"{#MyAppDir}\"');
      RegWriteStringValue(HKEY_LOCAL_MACHINE, ExpandConstant('Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1'), 'Inno Setup: App Path', '"{#MyAppDir}"');
    end;

    WizardForm.StatusLabel.Caption := 'Restrict permissions on agent config file...'
    Exec('icacls', '"'+ExpandConstant('{app}\{#AgentConfigFileName}')+'" /inheritance:d', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('icacls', '"'+ExpandConstant('{app}\{#AgentConfigFileName}')+'" /remove:g *S-1-5-32-545', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    { install and start services if it is a new installation }
    if InstallService then
    begin
      WizardForm.StatusLabel.Caption := 'Register service...'
      Exec(ExpandConstant('{#MyAppDir}\service-wrapper.exe'), '--startup auto install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

      { do not start service if corresponding parameter is set in .inf - for usage in $OEM$ Windows setup }
      if not DoNotStartService then
      begin
        WizardForm.StatusLabel.Caption := 'Start service...'
        Exec(ExpandConstant('{#MyAppDir}\service-wrapper.exe'), 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      end;
    end
    else
    begin
      if RestartService then
      begin
        { schedule agent restart with .new directory movement - this must be done with ewNoWait for OCO self-update so that the job gracefully finishes before restarting the agent }
        WizardForm.StatusLabel.Caption := 'Restarting service...'
        Exec('cmd.exe', '/c ping -n 5 127.0.0.1 & net stop oco-agent & rd /s /q "C:\Program Files\OCO Agent" & move "C:\Program Files\OCO Agent.new" "C:\Program Files\OCO Agent" & net start oco-agent', '', SW_HIDE, ewNoWait, ResultCode);
      end;
    end;
  end;
end;
