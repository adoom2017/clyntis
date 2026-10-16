Var ClyntisRestoreService
!define CLYNTIS_INSTALL_SECURITY_SCRIPT "${__FILEDIR__}\install-security.ps1"

!macro CLYNTIS_PROTECT_INSTALL_DIRECTORY ACTION
  InitPluginsDir
  File /oname=$PLUGINSDIR\clyntis-install-security.ps1 "${CLYNTIS_INSTALL_SECURITY_SCRIPT}"
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\clyntis-install-security.ps1" -InstallDirectory "$INSTDIR" -Action ${ACTION}'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not protect the installation directory.$\r$\n$1"
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  StrCpy $ClyntisRestoreService "0"
  !insertmacro CLYNTIS_PROTECT_INSTALL_DIRECTORY Prepare
  IfFileExists "$INSTDIR\clyntis-service.exe" 0 clyntis_install_continue
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query org.clyntis.desktop.service'
  Pop $0
  Pop $1
  ${If} $0 == 0
    StrCpy $ClyntisRestoreService "1"
  ${ElseIf} $0 == 1060
    Goto clyntis_install_continue
  ${Else}
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not query the network service.$\r$\n$1"
    Abort
  ${EndIf}
  ExecWait '"$INSTDIR\clyntis-service.exe" --uninstall' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not restore network settings. Close the app and retry."
    Abort
  ${EndIf}
  clyntis_install_continue:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro CLYNTIS_PROTECT_INSTALL_DIRECTORY Finalize
  ${If} $ClyntisRestoreService == "1"
    ExecWait '"$INSTDIR\clyntis-service.exe" --install' $0
    ${If} $0 != 0
      MessageBox MB_OK|MB_ICONEXCLAMATION "Please repair the network service from Clyntis Settings."
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query org.clyntis.desktop.service'
  Pop $0
  Pop $1
  ${If} $0 == 1060
    Goto clyntis_uninstall_continue
  ${ElseIf} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not query the network service.$\r$\n$1"
    Abort
  ${EndIf}
  IfFileExists "$INSTDIR\clyntis-service.exe" clyntis_uninstall_service
  MessageBox MB_OK|MB_ICONSTOP "The network service is registered but its program is missing. Repair Clyntis before uninstalling."
  Abort
  clyntis_uninstall_service:
  ExecWait '"$INSTDIR\clyntis-service.exe" --uninstall' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not restore network settings. Uninstallation was cancelled."
    Abort
  ${EndIf}
  clyntis_uninstall_continue:
!macroend
