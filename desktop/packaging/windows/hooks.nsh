Var ClyntisRestoreService
!macro NSIS_HOOK_PREINSTALL
  StrCpy $ClyntisRestoreService "0"
  IfFileExists "$INSTDIR\clyntis-service.exe" 0 clyntis_install_continue
  nsExec::ExecToStack 'sc.exe query org.clyntis.desktop.service'
  Pop $0
  Pop $1
  ${If} $0 == 0
    StrCpy $ClyntisRestoreService "1"
  ${EndIf}
  ExecWait '"$INSTDIR\clyntis-service.exe" --uninstall' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not restore network settings. Close the app and retry."
    Abort
  ${EndIf}
  clyntis_install_continue:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ${If} $ClyntisRestoreService == "1"
    ExecWait '"$INSTDIR\clyntis-service.exe" --install' $0
    ${If} $0 != 0
      MessageBox MB_OK|MB_ICONEXCLAMATION "Please repair the network service from Clyntis Settings."
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\clyntis-service.exe" 0 clyntis_uninstall_continue
  ExecWait '"$INSTDIR\clyntis-service.exe" --uninstall' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "Clyntis could not restore network settings. Uninstallation was cancelled."
    Abort
  ${EndIf}
  clyntis_uninstall_continue:
!macroend
