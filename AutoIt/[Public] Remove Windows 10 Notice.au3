#Region AutoIt3Wrapper directives section
#AutoIt3Wrapper_UseUpx=Y
#AutoIt3Wrapper_Compression=4
#AutoIt3Wrapper_Icon=icon.ico
#AutoIt3Wrapper_Res_LegalCopyright=(C) 2015 Juno_okyo. All rights reserved.
#AutoIt3Wrapper_Res_Comment=Developed by Juno_okyo
#AutoIt3Wrapper_Res_Description=Disable GWX.exe auto-start to remove notice about Windows 10 on Tray Menu in Windows 7/8.
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_Res_FileVersion_AutoIncrement=Y
#AutoIt3Wrapper_Res_ProductVersion=1.0.0.0;=>Edit
#AutoIt3Wrapper_Res_Field=InternalName|juno_okyo.exe;=>Edit
#AutoIt3Wrapper_Res_Field=OriginalFilename|juno_okyo.exe;=>Edit
#AutoIt3Wrapper_Res_Field=ProductName|Windows 10 Notice Remover;=>Edit
#AutoIt3Wrapper_Res_Field=CompanyName|J2TeaM
#AutoIt3Wrapper_Res_Field=Website|http://junookyo.blogspot.com/
#AutoIt3Wrapper_Res_SaveSource=N
#EndRegion AutoIt3Wrapper directives section

#NoTrayIcon
#include "lib.au3"

#Region === OPTIONS ===
_Singleton(@ScriptName)
Opt('MustDeclareVars', 1)
Opt('WinTitleMatchMode', 2)
Opt('GUICloseOnESC', 0)
Opt('GUIOnEventMode', 1)
Opt('TrayOnEventMode', 1)
#EndRegion

If Not FileExists(@TempDir & '\RWN-logo.png') Then
	FileInstall('.\logo.png', @TempDir & '\RWN-logo.png')
EndIf

Global $VERSION = '1.0.0'
Global $GWX_KEY = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GWX.exe'
Global $GWX_NAME = 'Debugger'
Global $GWX_CMD = 'cmd /c echo'

#Region === GUI ===
Global $MainForm = GUICreate("[J-Soft] Remove Win 10 Notice", 312, 220, -1, -1, -1, BitOR(0x00000008, 0x00000100))
GUISetFont(12, 400, 0, "Arial")
GUISetOnEvent($GUI_EVENT_CLOSE, "MainFormClose")
Global $logo = GUICtrlCreatePic('', 0, 0, 312, 155)
_SetImage(-1, @TempDir & '\RWN-logo.png')
GUICtrlSetOnEvent(-1, 'OpenHomePage')
Global $Button1 = GUICtrlCreateButton("Remove", 5, 165, 90, 25)
GUICtrlSetOnEvent(-1, "Button1Click")
GUICtrlSetCursor(-1, 0)
GUICtrlSetState(-1, 512)
Global $Button2 = GUICtrlCreateButton("Restore", 110, 165, 90, 25)
GUICtrlSetOnEvent(-1, "Button2Click")
GUICtrlSetCursor(-1, 0)
Global $Button3 = GUICtrlCreateButton("About", 215, 165, 90, 25)
GUICtrlSetOnEvent(-1, "Button3Click")
GUICtrlSetCursor(-1, 0)
GUICtrlCreateStatusBar($MainForm, 165)
GUISetState(@SW_SHOW)
#EndRegion

While 1
	Sleep(100)
WEnd

#Region === FUNCTIONS ===
Func OpenHomePage()
	ShellExecute('http://junookyo.blogspot.com/')
EndFunc   ;==>OpenHomePage

Func Button1Click()
	RegRead($GWX_KEY, $GWX_NAME)
	If @error Then RegWrite($GWX_KEY, $GWX_NAME, 'REG_SZ', $GWX_CMD)
	Local $msg = "It'll never run again!" & @CRLF & 'Do you want restart to apply all changes now?'
	If MsgBox(32 + 4 + 262144, 'Done', $msg, 0, $MainForm) = 6 Then
		Shutdown(6)
	EndIf
EndFunc   ;==>Button1Click

Func Button2Click()
	RegRead($GWX_KEY, $GWX_NAME)
	If Not @error Then RegDelete($GWX_KEY)
	MsgBox(64 + 262144, 'Done', "It'll show again on next time when Windows start!", 0, $MainForm)
EndFunc   ;==>Button2Click

Func Button3Click()
	Local $br = @CRLF & @CRLF
	Local $about = 'Windows 10 Notice Remover' & $br & 'Version: ' & $VERSION & $br & 'Copyright: ' & @YEAR & ' J2TeaM' & $br & 'Home Page: http://junookyo.blogspot.com/'
	MsgBox(64 + 262144, 'About', $about, 0, $MainForm)
EndFunc   ;==>Button3Click

Func MainFormClose()
	Exit
EndFunc   ;==>MainFormClose
#EndRegion
