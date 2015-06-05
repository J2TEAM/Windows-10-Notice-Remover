Global Const $tagRECT = "struct;long Left;long Top;long Right;long Bottom;endstruct"
Global Const $tagGDIPSTARTUPINPUT = "uint Version;ptr Callback;bool NoThread;bool NoCodecs"
Global Const $tagREBARBANDINFO = "uint cbSize;uint fMask;uint fStyle;dword clrFore;dword clrBack;ptr lpText;uint cch;" & "int iImage;hwnd hwndChild;uint cxMinChild;uint cyMinChild;uint cx;handle hbmBack;uint wID;uint cyChild;uint cyMaxChild;" & "uint cyIntegral;uint cxIdeal;lparam lParam;uint cxHeader" & ((@OSVersion = "WIN_XP") ? "" : ";" & $tagRECT & ";uint uChevronState")
Global Const $tagSECURITY_ATTRIBUTES = "dword Length;ptr Descriptor;bool InheritHandle"
Func _WinAPI_GetLastError($iError = @error, $iExtended = @extended)
	Local $aResult = DllCall("kernel32.dll", "dword", "GetLastError")
	Return SetError($iError, $iExtended, $aResult[0])
EndFunc   ;==>_WinAPI_GetLastError
Func _WinAPI_SetLastError($iErrorCode, $iError = @error, $iExtended = @extended)
	DllCall("kernel32.dll", "none", "SetLastError", "dword", $iErrorCode)
	Return SetError($iError, $iExtended, Null)
EndFunc   ;==>_WinAPI_SetLastError
Func _Singleton($sOccurenceName, $iFlag = 0)
	Local Const $ERROR_ALREADY_EXISTS = 183
	Local Const $SECURITY_DESCRIPTOR_REVISION = 1
	Local $tSecurityAttributes = 0
	If BitAND($iFlag, 2) Then
		Local $tSecurityDescriptor = DllStructCreate("byte;byte;word;ptr[4]")
		Local $aRet = DllCall("advapi32.dll", "bool", "InitializeSecurityDescriptor", "struct*", $tSecurityDescriptor, "dword", $SECURITY_DESCRIPTOR_REVISION)
		If @error Then Return SetError(@error, @extended, 0)
		If $aRet[0] Then
			$aRet = DllCall("advapi32.dll", "bool", "SetSecurityDescriptorDacl", "struct*", $tSecurityDescriptor, "bool", 1, "ptr", 0, "bool", 0)
			If @error Then Return SetError(@error, @extended, 0)
			If $aRet[0] Then
				$tSecurityAttributes = DllStructCreate($tagSECURITY_ATTRIBUTES)
				DllStructSetData($tSecurityAttributes, 1, DllStructGetSize($tSecurityAttributes))
				DllStructSetData($tSecurityAttributes, 2, DllStructGetPtr($tSecurityDescriptor))
				DllStructSetData($tSecurityAttributes, 3, 0)
			EndIf
		EndIf
	EndIf
	Local $aHandle = DllCall("kernel32.dll", "handle", "CreateMutexW", "struct*", $tSecurityAttributes, "bool", 1, "wstr", $sOccurenceName)
	If @error Then Return SetError(@error, @extended, 0)
	Local $aLastError = DllCall("kernel32.dll", "dword", "GetLastError")
	If @error Then Return SetError(@error, @extended, 0)
	If $aLastError[0] = $ERROR_ALREADY_EXISTS Then
		If BitAND($iFlag, 1) Then
			DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $aHandle[0])
			If @error Then Return SetError(@error, @extended, 0)
			Return SetError($aLastError[0], $aLastError[0], 0)
		Else
			Exit -1
		EndIf
	EndIf
	Return $aHandle[0]
EndFunc   ;==>_Singleton
Global Const $GUI_EVENT_CLOSE = -3
Global Enum $SECURITYANONYMOUS = 0, $SECURITYIDENTIFICATION, $SECURITYIMPERSONATION, $SECURITYDELEGATION
Func _Security__AdjustTokenPrivileges($hToken, $bDisableAll, $pNewState, $iBufferLen, $pPrevState = 0, $pRequired = 0)
	Local $aCall = DllCall("advapi32.dll", "bool", "AdjustTokenPrivileges", "handle", $hToken, "bool", $bDisableAll, "struct*", $pNewState, "dword", $iBufferLen, "struct*", $pPrevState, "struct*", $pRequired)
	If @error Then Return SetError(@error, @extended, False)
	Return Not ($aCall[0] = 0)
EndFunc   ;==>_Security__AdjustTokenPrivileges
Func _Security__ImpersonateSelf($iLevel = $SECURITYIMPERSONATION)
	Local $aCall = DllCall("advapi32.dll", "bool", "ImpersonateSelf", "int", $iLevel)
	If @error Then Return SetError(@error, @extended, False)
	Return Not ($aCall[0] = 0)
EndFunc   ;==>_Security__ImpersonateSelf
Func _Security__LookupPrivilegeValue($sSystem, $sName)
	Local $aCall = DllCall("advapi32.dll", "bool", "LookupPrivilegeValueW", "wstr", $sSystem, "wstr", $sName, "int64*", 0)
	If @error Or Not $aCall[0] Then Return SetError(@error, @extended, 0)
	Return $aCall[3]
EndFunc   ;==>_Security__LookupPrivilegeValue
Func _Security__OpenThreadToken($iAccess, $hThread = 0, $bOpenAsSelf = False)
	If $hThread = 0 Then
		Local $aResult = DllCall("kernel32.dll", "handle", "GetCurrentThread")
		If @error Then Return SetError(@error + 10, @extended, 0)
		$hThread = $aResult[0]
	EndIf
	Local $aCall = DllCall("advapi32.dll", "bool", "OpenThreadToken", "handle", $hThread, "dword", $iAccess, "bool", $bOpenAsSelf, "handle*", 0)
	If @error Or Not $aCall[0] Then Return SetError(@error, @extended, 0)
	Return $aCall[4]
EndFunc   ;==>_Security__OpenThreadToken
Func _Security__OpenThreadTokenEx($iAccess, $hThread = 0, $bOpenAsSelf = False)
	Local $hToken = _Security__OpenThreadToken($iAccess, $hThread, $bOpenAsSelf)
	If $hToken = 0 Then
		Local Const $ERROR_NO_TOKEN = 1008
		If _WinAPI_GetLastError() <> $ERROR_NO_TOKEN Then Return SetError(20, _WinAPI_GetLastError(), 0)
		If Not _Security__ImpersonateSelf() Then Return SetError(@error + 10, _WinAPI_GetLastError(), 0)
		$hToken = _Security__OpenThreadToken($iAccess, $hThread, $bOpenAsSelf)
		If $hToken = 0 Then Return SetError(@error, _WinAPI_GetLastError(), 0)
	EndIf
	Return $hToken
EndFunc   ;==>_Security__OpenThreadTokenEx
Func _Security__SetPrivilege($hToken, $sPrivilege, $bEnable)
	Local $iLUID = _Security__LookupPrivilegeValue("", $sPrivilege)
	If $iLUID = 0 Then Return SetError(@error + 10, @extended, False)
	Local Const $tagTOKEN_PRIVILEGES = "dword Count;align 4;int64 LUID;dword Attributes"
	Local $tCurrState = DllStructCreate($tagTOKEN_PRIVILEGES)
	Local $iCurrState = DllStructGetSize($tCurrState)
	Local $tPrevState = DllStructCreate($tagTOKEN_PRIVILEGES)
	Local $iPrevState = DllStructGetSize($tPrevState)
	Local $tRequired = DllStructCreate("int Data")
	DllStructSetData($tCurrState, "Count", 1)
	DllStructSetData($tCurrState, "LUID", $iLUID)
	If Not _Security__AdjustTokenPrivileges($hToken, False, $tCurrState, $iCurrState, $tPrevState, $tRequired) Then Return SetError(2, @error, False)
	DllStructSetData($tPrevState, "Count", 1)
	DllStructSetData($tPrevState, "LUID", $iLUID)
	Local $iAttributes = DllStructGetData($tPrevState, "Attributes")
	If $bEnable Then
		$iAttributes = BitOR($iAttributes, 0x00000002)
	Else
		$iAttributes = BitAND($iAttributes, BitNOT(0x00000002))
	EndIf
	DllStructSetData($tPrevState, "Attributes", $iAttributes)
	If Not _Security__AdjustTokenPrivileges($hToken, False, $tPrevState, $iPrevState, $tCurrState, $tRequired) Then Return SetError(3, @error, False)
	Return True
EndFunc   ;==>_Security__SetPrivilege
Global Const $tagMEMMAP = "handle hProc;ulong_ptr Size;ptr Mem"
Func _MemFree(ByRef $tMemMap)
	Local $pMemory = DllStructGetData($tMemMap, "Mem")
	Local $hProcess = DllStructGetData($tMemMap, "hProc")
	Local $bResult = _MemVirtualFreeEx($hProcess, $pMemory, 0, 0x00008000)
	DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hProcess)
	If @error Then Return SetError(@error, @extended, False)
	Return $bResult
EndFunc   ;==>_MemFree
Func _MemInit($hWnd, $iSize, ByRef $tMemMap)
	Local $aResult = DllCall("User32.dll", "dword", "GetWindowThreadProcessId", "hwnd", $hWnd, "dword*", 0)
	If @error Then Return SetError(@error + 10, @extended, 0)
	Local $iProcessID = $aResult[2]
	If $iProcessID = 0 Then Return SetError(1, 0, 0)
	Local $iAccess = BitOR(0x00000008, 0x00000010, 0x00000020)
	Local $hProcess = __Mem_OpenProcess($iAccess, False, $iProcessID, True)
	Local $iAlloc = BitOR(0x00002000, 0x00001000)
	Local $pMemory = _MemVirtualAllocEx($hProcess, 0, $iSize, $iAlloc, 0x00000004)
	If $pMemory = 0 Then Return SetError(2, 0, 0)
	$tMemMap = DllStructCreate($tagMEMMAP)
	DllStructSetData($tMemMap, "hProc", $hProcess)
	DllStructSetData($tMemMap, "Size", $iSize)
	DllStructSetData($tMemMap, "Mem", $pMemory)
	Return $pMemory
EndFunc   ;==>_MemInit
Func _MemWrite(ByRef $tMemMap, $pSrce, $pDest = 0, $iSize = 0, $sSrce = "struct*")
	If $pDest = 0 Then $pDest = DllStructGetData($tMemMap, "Mem")
	If $iSize = 0 Then $iSize = DllStructGetData($tMemMap, "Size")
	Local $aResult = DllCall("kernel32.dll", "bool", "WriteProcessMemory", "handle", DllStructGetData($tMemMap, "hProc"), "ptr", $pDest, $sSrce, $pSrce, "ulong_ptr", $iSize, "ulong_ptr*", 0)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc   ;==>_MemWrite
Func _MemVirtualAllocEx($hProcess, $pAddress, $iSize, $iAllocation, $iProtect)
	Local $aResult = DllCall("kernel32.dll", "ptr", "VirtualAllocEx", "handle", $hProcess, "ptr", $pAddress, "ulong_ptr", $iSize, "dword", $iAllocation, "dword", $iProtect)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_MemVirtualAllocEx
Func _MemVirtualFreeEx($hProcess, $pAddress, $iSize, $iFreeType)
	Local $aResult = DllCall("kernel32.dll", "bool", "VirtualFreeEx", "handle", $hProcess, "ptr", $pAddress, "ulong_ptr", $iSize, "dword", $iFreeType)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc   ;==>_MemVirtualFreeEx
Func __Mem_OpenProcess($iAccess, $bInherit, $iProcessID, $bDebugPriv = False)
	Local $aResult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iAccess, "bool", $bInherit, "dword", $iProcessID)
	If @error Then Return SetError(@error + 10, @extended, 0)
	If $aResult[0] Then Return $aResult[0]
	If Not $bDebugPriv Then Return 0
	Local $hToken = _Security__OpenThreadTokenEx(BitOR(0x00000020, 0x00000008))
	If @error Then Return SetError(@error + 20, @extended, 0)
	_Security__SetPrivilege($hToken, "SeDebugPrivilege", True)
	Local $iError = @error
	Local $iLastError = @extended
	Local $iRet = 0
	If Not @error Then
		$aResult = DllCall("kernel32.dll", "handle", "OpenProcess", "dword", $iAccess, "bool", $bInherit, "dword", $iProcessID)
		$iError = @error
		$iLastError = @extended
		If $aResult[0] Then $iRet = $aResult[0]
		_Security__SetPrivilege($hToken, "SeDebugPrivilege", False)
		If @error Then
			$iError = @error + 30
			$iLastError = @extended
		EndIf
	Else
		$iError = @error + 40
	EndIf
	DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hToken)
	Return SetError($iError, $iLastError, $iRet)
EndFunc   ;==>__Mem_OpenProcess
Func _SendMessage($hWnd, $iMsg, $wParam = 0, $lParam = 0, $iReturn = 0, $wParamType = "wparam", $lParamType = "lparam", $sReturnType = "lresult")
	Local $aResult = DllCall("user32.dll", $sReturnType, "SendMessageW", "hwnd", $hWnd, "uint", $iMsg, $wParamType, $wParam, $lParamType, $lParam)
	If @error Then Return SetError(@error, @extended, "")
	If $iReturn >= 0 And $iReturn <= 4 Then Return $aResult[$iReturn]
	Return $aResult
EndFunc   ;==>_SendMessage
Global Const $__STATUSBARCONSTANT_WM_USER = 0X400
Global Const $SB_GETUNICODEFORMAT = 0x2000 + 6
Global Const $SB_ISSIMPLE = ($__STATUSBARCONSTANT_WM_USER + 14)
Global Const $SB_SETMINHEIGHT = ($__STATUSBARCONSTANT_WM_USER + 8)
Global Const $SB_SETPARTS = ($__STATUSBARCONSTANT_WM_USER + 4)
Global Const $SB_SETTEXTA = ($__STATUSBARCONSTANT_WM_USER + 1)
Global Const $SB_SETTEXTW = ($__STATUSBARCONSTANT_WM_USER + 11)
Global Const $SB_SETTEXT = $SB_SETTEXTA
Global Const $SB_SIMPLEID = 0xff
Global Const $HGDI_ERROR = Ptr(-1)
Global Const $INVALID_HANDLE_VALUE = Ptr(-1)
Global Const $LLKHF_EXTENDED = BitShift(0x0100, 8)
Global Const $LLKHF_ALTDOWN = BitShift(0x2000, 8)
Global Const $LLKHF_UP = BitShift(0x8000, 8)
Global Const $GWL_STYLE = 0xFFFFFFF0
Global $__g_aInProcess_WinAPI[64][2] = [[0, 0]]
Func _WinAPI_CreateWindowEx($iExStyle, $sClass, $sName, $iStyle, $iX, $iY, $iWidth, $iHeight, $hParent, $hMenu = 0, $hInstance = 0, $pParam = 0)
	If $hInstance = 0 Then $hInstance = _WinAPI_GetModuleHandle("")
	Local $aResult = DllCall("user32.dll", "hwnd", "CreateWindowExW", "dword", $iExStyle, "wstr", $sClass, "wstr", $sName, "dword", $iStyle, "int", $iX, "int", $iY, "int", $iWidth, "int", $iHeight, "hwnd", $hParent, "handle", $hMenu, "handle", $hInstance, "ptr", $pParam)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_CreateWindowEx
Func _WinAPI_DeleteObject($hObject)
	Local $aResult = DllCall("gdi32.dll", "bool", "DeleteObject", "handle", $hObject)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_DeleteObject
Func _WinAPI_DestroyIcon($hIcon)
	Local $aResult = DllCall("user32.dll", "bool", "DestroyIcon", "handle", $hIcon)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_DestroyIcon
Func _WinAPI_GetModuleHandle($sModuleName)
	Local $sModuleNameType = "wstr"
	If $sModuleName = "" Then
		$sModuleName = 0
		$sModuleNameType = "ptr"
	EndIf
	Local $aResult = DllCall("kernel32.dll", "handle", "GetModuleHandleW", $sModuleNameType, $sModuleName)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_GetModuleHandle
Func _WinAPI_GetParent($hWnd)
	Local $aResult = DllCall("user32.dll", "hwnd", "GetParent", "hwnd", $hWnd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_GetParent
Func _WinAPI_GetWindow($hWnd, $iCmd)
	Local $aResult = DllCall("user32.dll", "hwnd", "GetWindow", "hwnd", $hWnd, "uint", $iCmd)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_GetWindow
Func _WinAPI_GetWindowLong($hWnd, $iIndex)
	Local $sFuncName = "GetWindowLongW"
	If @AutoItX64 Then $sFuncName = "GetWindowLongPtrW"
	Local $aResult = DllCall("user32.dll", "long_ptr", $sFuncName, "hwnd", $hWnd, "int", $iIndex)
	If @error Or Not $aResult[0] Then Return SetError(@error + 10, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_GetWindowLong
Func _WinAPI_GetWindowThreadProcessId($hWnd, ByRef $iPID)
	Local $aResult = DllCall("user32.dll", "dword", "GetWindowThreadProcessId", "hwnd", $hWnd, "dword*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	$iPID = $aResult[2]
	Return $aResult[0]
EndFunc   ;==>_WinAPI_GetWindowThreadProcessId
Func _WinAPI_InProcess($hWnd, ByRef $hLastWnd)
	If $hWnd = $hLastWnd Then Return True
	For $iI = $__g_aInProcess_WinAPI[0][0] To 1 Step -1
		If $hWnd = $__g_aInProcess_WinAPI[$iI][0] Then
			If $__g_aInProcess_WinAPI[$iI][1] Then
				$hLastWnd = $hWnd
				Return True
			Else
				Return False
			EndIf
		EndIf
	Next
	Local $iPID
	_WinAPI_GetWindowThreadProcessId($hWnd, $iPID)
	Local $iCount = $__g_aInProcess_WinAPI[0][0] + 1
	If $iCount >= 64 Then $iCount = 1
	$__g_aInProcess_WinAPI[0][0] = $iCount
	$__g_aInProcess_WinAPI[$iCount][0] = $hWnd
	$__g_aInProcess_WinAPI[$iCount][1] = ($iPID = @AutoItPID)
	Return $__g_aInProcess_WinAPI[$iCount][1]
EndFunc   ;==>_WinAPI_InProcess
Func _WinAPI_InvalidateRect($hWnd, $tRect = 0, $bErase = True)
	Local $aResult = DllCall("user32.dll", "bool", "InvalidateRect", "hwnd", $hWnd, "struct*", $tRect, "bool", $bErase)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_InvalidateRect
Func _WinAPI_MoveWindow($hWnd, $iX, $iY, $iWidth, $iHeight, $bRepaint = True)
	Local $aResult = DllCall("user32.dll", "bool", "MoveWindow", "hwnd", $hWnd, "int", $iX, "int", $iY, "int", $iWidth, "int", $iHeight, "bool", $bRepaint)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_MoveWindow
Func _WinAPI_SetWindowLong($hWnd, $iIndex, $iValue)
	_WinAPI_SetLastError(0)
	Local $sFuncName = "SetWindowLongW"
	If @AutoItX64 Then $sFuncName = "SetWindowLongPtrW"
	Local $aResult = DllCall("user32.dll", "long_ptr", $sFuncName, "hwnd", $hWnd, "int", $iIndex, "long_ptr", $iValue)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aResult[0]
EndFunc   ;==>_WinAPI_SetWindowLong
Global $__g_aUDF_GlobalIDs_Used[16][55535 + 2 + 1]
Func __UDF_GetNextGlobalID($hWnd)
	Local $nCtrlID, $iUsedIndex = -1, $bAllUsed = True
	If Not WinExists($hWnd) Then Return SetError(-1, -1, 0)
	For $iIndex = 0 To 16 - 1
		If $__g_aUDF_GlobalIDs_Used[$iIndex][0] <> 0 Then
			If Not WinExists($__g_aUDF_GlobalIDs_Used[$iIndex][0]) Then
				For $x = 0 To UBound($__g_aUDF_GlobalIDs_Used, 2) - 1
					$__g_aUDF_GlobalIDs_Used[$iIndex][$x] = 0
				Next
				$__g_aUDF_GlobalIDs_Used[$iIndex][1] = 10000
				$bAllUsed = False
			EndIf
		EndIf
	Next
	For $iIndex = 0 To 16 - 1
		If $__g_aUDF_GlobalIDs_Used[$iIndex][0] = $hWnd Then
			$iUsedIndex = $iIndex
			ExitLoop
		EndIf
	Next
	If $iUsedIndex = -1 Then
		For $iIndex = 0 To 16 - 1
			If $__g_aUDF_GlobalIDs_Used[$iIndex][0] = 0 Then
				$__g_aUDF_GlobalIDs_Used[$iIndex][0] = $hWnd
				$__g_aUDF_GlobalIDs_Used[$iIndex][1] = 10000
				$bAllUsed = False
				$iUsedIndex = $iIndex
				ExitLoop
			EndIf
		Next
	EndIf
	If $iUsedIndex = -1 And $bAllUsed Then Return SetError(16, 0, 0)
	If $__g_aUDF_GlobalIDs_Used[$iUsedIndex][1] = 10000 + 55535 Then
		For $iIDIndex = 2 To UBound($__g_aUDF_GlobalIDs_Used, 2) - 1
			If $__g_aUDF_GlobalIDs_Used[$iUsedIndex][$iIDIndex] = 0 Then
				$nCtrlID = ($iIDIndex - 2) + 10000
				$__g_aUDF_GlobalIDs_Used[$iUsedIndex][$iIDIndex] = $nCtrlID
				Return $nCtrlID
			EndIf
		Next
		Return SetError(-1, 55535, 0)
	EndIf
	$nCtrlID = $__g_aUDF_GlobalIDs_Used[$iUsedIndex][1]
	$__g_aUDF_GlobalIDs_Used[$iUsedIndex][1] += 1
	$__g_aUDF_GlobalIDs_Used[$iUsedIndex][($nCtrlID - 10000) + 2] = $nCtrlID
	Return $nCtrlID
EndFunc   ;==>__UDF_GetNextGlobalID
Global $__g_hSBLastWnd
Global Const $__STATUSBARCONSTANT_ClassName = "msctls_statusbar32"
Func _GUICtrlStatusBar_Create($hWnd, $vPartEdge = -1, $vPartText = "", $iStyles = -1, $iExStyles = -1)
	If Not IsHWnd($hWnd) Then Return SetError(1, 0, 0)
	Local $iStyle = BitOR(0x40000000, 0x10000000)
	If $iStyles = -1 Then $iStyles = 0x00000000
	If $iExStyles = -1 Then $iExStyles = 0x00000000
	Local $aPartWidth[1], $aPartText[1]
	If @NumParams > 1 Then
		If IsArray($vPartEdge) Then
			$aPartWidth = $vPartEdge
		Else
			$aPartWidth[0] = $vPartEdge
		EndIf
		If @NumParams = 2 Then
			ReDim $aPartText[UBound($aPartWidth)]
		Else
			If IsArray($vPartText) Then
				$aPartText = $vPartText
			Else
				$aPartText[0] = $vPartText
			EndIf
			If UBound($aPartWidth) <> UBound($aPartText) Then
				Local $iLast
				If UBound($aPartWidth) > UBound($aPartText) Then
					$iLast = UBound($aPartText)
					ReDim $aPartText[UBound($aPartWidth)]
					For $x = $iLast To UBound($aPartText) - 1
						$aPartWidth[$x] = ""
					Next
				Else
					$iLast = UBound($aPartWidth)
					ReDim $aPartWidth[UBound($aPartText)]
					For $x = $iLast To UBound($aPartWidth) - 1
						$aPartWidth[$x] = $aPartWidth[$x - 1] + 75
					Next
					$aPartWidth[UBound($aPartText) - 1] = -1
				EndIf
			EndIf
		EndIf
		If Not IsHWnd($hWnd) Then $hWnd = HWnd($hWnd)
		If @NumParams > 3 Then $iStyle = BitOR($iStyle, $iStyles)
	EndIf
	Local $nCtrlID = __UDF_GetNextGlobalID($hWnd)
	If @error Then Return SetError(@error, @extended, 0)
	Local $hWndSBar = _WinAPI_CreateWindowEx($iExStyles, $__STATUSBARCONSTANT_ClassName, "", $iStyle, 0, 0, 0, 0, $hWnd, $nCtrlID)
	If @error Then Return SetError(@error, @extended, 0)
	If @NumParams > 1 Then
		_GUICtrlStatusBar_SetParts($hWndSBar, UBound($aPartWidth), $aPartWidth)
		For $x = 0 To UBound($aPartText) - 1
			_GUICtrlStatusBar_SetText($hWndSBar, $aPartText[$x], $x)
		Next
	EndIf
	Return $hWndSBar
EndFunc   ;==>_GUICtrlStatusBar_Create
Func _GUICtrlStatusBar_GetUnicodeFormat($hWnd)
	Return _SendMessage($hWnd, $SB_GETUNICODEFORMAT) <> 0
EndFunc   ;==>_GUICtrlStatusBar_GetUnicodeFormat
Func _GUICtrlStatusBar_IsSimple($hWnd)
	Return _SendMessage($hWnd, $SB_ISSIMPLE) <> 0
EndFunc   ;==>_GUICtrlStatusBar_IsSimple
Func _GUICtrlStatusBar_Resize($hWnd)
	_SendMessage($hWnd, 0x05)
EndFunc   ;==>_GUICtrlStatusBar_Resize
Func _GUICtrlStatusBar_SetMinHeight($hWnd, $iMinHeight)
	_SendMessage($hWnd, $SB_SETMINHEIGHT, $iMinHeight)
	_GUICtrlStatusBar_Resize($hWnd)
EndFunc   ;==>_GUICtrlStatusBar_SetMinHeight
Func _GUICtrlStatusBar_SetParts($hWnd, $aParts = -1, $aPartWidth = 25)
	Local $tParts, $iParts = 1
	If IsArray($aParts) <> 0 Then
		$aParts[UBound($aParts) - 1] = -1
		$iParts = UBound($aParts)
		$tParts = DllStructCreate("int[" & $iParts & "]")
		For $x = 0 To $iParts - 2
			DllStructSetData($tParts, 1, $aParts[$x], $x + 1)
		Next
		DllStructSetData($tParts, 1, -1, $iParts)
	ElseIf IsArray($aPartWidth) <> 0 Then
		$iParts = UBound($aPartWidth)
		$tParts = DllStructCreate("int[" & $iParts & "]")
		For $x = 0 To $iParts - 2
			DllStructSetData($tParts, 1, $aPartWidth[$x], $x + 1)
		Next
		DllStructSetData($tParts, 1, -1, $iParts)
	ElseIf $aParts > 1 Then
		$iParts = $aParts
		$tParts = DllStructCreate("int[" & $iParts & "]")
		For $x = 1 To $iParts - 1
			DllStructSetData($tParts, 1, $aPartWidth * $x, $x)
		Next
		DllStructSetData($tParts, 1, -1, $iParts)
	Else
		$tParts = DllStructCreate("int")
		DllStructSetData($tParts, $iParts, -1)
	EndIf
	If _WinAPI_InProcess($hWnd, $__g_hSBLastWnd) Then
		_SendMessage($hWnd, $SB_SETPARTS, $iParts, $tParts, 0, "wparam", "struct*")
	Else
		Local $iSize = DllStructGetSize($tParts)
		Local $tMemMap
		Local $pMemory = _MemInit($hWnd, $iSize, $tMemMap)
		_MemWrite($tMemMap, $tParts)
		_SendMessage($hWnd, $SB_SETPARTS, $iParts, $pMemory, 0, "wparam", "ptr")
		_MemFree($tMemMap)
	EndIf
	_GUICtrlStatusBar_Resize($hWnd)
	Return True
EndFunc   ;==>_GUICtrlStatusBar_SetParts
Func _GUICtrlStatusBar_SetText($hWnd, $sText = "", $iPart = 0, $iUFlag = 0)
	Local $bUnicode = _GUICtrlStatusBar_GetUnicodeFormat($hWnd)
	Local $iBuffer = StringLen($sText) + 1
	Local $tText
	If $bUnicode Then
		$tText = DllStructCreate("wchar Text[" & $iBuffer & "]")
		$iBuffer *= 2
	Else
		$tText = DllStructCreate("char Text[" & $iBuffer & "]")
	EndIf
	DllStructSetData($tText, "Text", $sText)
	If _GUICtrlStatusBar_IsSimple($hWnd) Then $iPart = $SB_SIMPLEID
	Local $iRet
	If _WinAPI_InProcess($hWnd, $__g_hSBLastWnd) Then
		$iRet = _SendMessage($hWnd, $SB_SETTEXTW, BitOR($iPart, $iUFlag), $tText, 0, "wparam", "struct*")
	Else
		Local $tMemMap
		Local $pMemory = _MemInit($hWnd, $iBuffer, $tMemMap)
		_MemWrite($tMemMap, $tText)
		If $bUnicode Then
			$iRet = _SendMessage($hWnd, $SB_SETTEXTW, BitOR($iPart, $iUFlag), $pMemory, 0, "wparam", "ptr")
		Else
			$iRet = _SendMessage($hWnd, $SB_SETTEXT, BitOR($iPart, $iUFlag), $pMemory, 0, "wparam", "ptr")
		EndIf
		_MemFree($tMemMap)
	EndIf
	Return $iRet <> 0
EndFunc   ;==>_GUICtrlStatusBar_SetText
Func GUICtrlCreateStatusBar($gui, $space = 280, $text = 'Developed by Juno_okyo', $copyright = 'J2TeaM')
	Local $statusBar = _GUICtrlStatusBar_Create($gui)
	Local $statusBar_PartsWidth[2] = [$space, -1]
	_GUICtrlStatusBar_SetParts($statusBar, $statusBar_PartsWidth)
	_GUICtrlStatusBar_SetText($statusBar, $text, 0)
	_GUICtrlStatusBar_SetText($statusBar, 'Copyright ' & Chr(169) & ' ' & @YEAR & ' ' & $copyright, 1)
	_GUICtrlStatusBar_SetMinHeight($statusBar, 3)
	Return $statusBar
EndFunc   ;==>GUICtrlCreateStatusBar
Global Const $tagOSVERSIONINFO = 'struct;dword OSVersionInfoSize;dword MajorVersion;dword MinorVersion;dword BuildNumber;dword PlatformId;wchar CSDVersion[128];endstruct'
Global Const $__WINVER = __WINVER()
Func __WINVER()
	Local $tOSVI = DllStructCreate($tagOSVERSIONINFO)
	DllStructSetData($tOSVI, 1, DllStructGetSize($tOSVI))
	Local $aRet = DllCall('kernel32.dll', 'bool', 'GetVersionExW', 'struct*', $tOSVI)
	If @error Or Not $aRet[0] Then Return SetError(@error, @extended, 0)
	Return BitOR(BitShift(DllStructGetData($tOSVI, 2), -8), DllStructGetData($tOSVI, 3))
EndFunc   ;==>__WINVER
Global $__g_hGDIPDll = 0
Global $__g_iGDIPRef = 0
Global $__g_iGDIPToken = 0
Global $__g_bGDIP_V1_0 = True
Func _GDIPlus_BitmapCreateFromFile($sFileName)
	Local $aResult = DllCall($__g_hGDIPDll, "int", "GdipCreateBitmapFromFile", "wstr", $sFileName, "handle*", 0)
	If @error Then Return SetError(@error, @extended, 0)
	If $aResult[0] Then Return SetError(10, $aResult[0], 0)
	Return $aResult[2]
EndFunc   ;==>_GDIPlus_BitmapCreateFromFile
Func _GDIPlus_BitmapCreateHBITMAPFromBitmap($hBitmap, $iARGB = 0xFF000000)
	Local $aResult = DllCall($__g_hGDIPDll, "int", "GdipCreateHBITMAPFromBitmap", "handle", $hBitmap, "handle*", 0, "dword", $iARGB)
	If @error Then Return SetError(@error, @extended, 0)
	If $aResult[0] Then Return SetError(10, $aResult[0], 0)
	Return $aResult[2]
EndFunc   ;==>_GDIPlus_BitmapCreateHBITMAPFromBitmap
Func _GDIPlus_ImageDispose($hImage)
	Local $aResult = DllCall($__g_hGDIPDll, "int", "GdipDisposeImage", "handle", $hImage)
	If @error Then Return SetError(@error, @extended, False)
	If $aResult[0] Then Return SetError(10, $aResult[0], False)
	Return True
EndFunc   ;==>_GDIPlus_ImageDispose
Func _GDIPlus_ImageGetHeight($hImage)
	Local $aResult = DllCall($__g_hGDIPDll, "int", "GdipGetImageHeight", "handle", $hImage, "uint*", 0)
	If @error Then Return SetError(@error, @extended, -1)
	If $aResult[0] Then Return SetError(10, $aResult[0], -1)
	Return $aResult[2]
EndFunc   ;==>_GDIPlus_ImageGetHeight
Func _GDIPlus_ImageGetWidth($hImage)
	Local $aResult = DllCall($__g_hGDIPDll, "int", "GdipGetImageWidth", "handle", $hImage, "uint*", -1)
	If @error Then Return SetError(@error, @extended, -1)
	If $aResult[0] Then Return SetError(10, $aResult[0], -1)
	Return $aResult[2]
EndFunc   ;==>_GDIPlus_ImageGetWidth
Func _GDIPlus_Shutdown()
	If $__g_hGDIPDll = 0 Then Return SetError(-1, -1, False)
	$__g_iGDIPRef -= 1
	If $__g_iGDIPRef = 0 Then
		DllCall($__g_hGDIPDll, "none", "GdiplusShutdown", "ulong_ptr", $__g_iGDIPToken)
		DllClose($__g_hGDIPDll)
		$__g_hGDIPDll = 0
	EndIf
	Return True
EndFunc   ;==>_GDIPlus_Shutdown
Func _GDIPlus_Startup($sGDIPDLL = Default, $bRetDllHandle = False)
	$__g_iGDIPRef += 1
	If $__g_iGDIPRef > 1 Then Return True
	If $sGDIPDLL = Default Then
		If @OSBuild > 4999 And @OSBuild < 7600 Then
			$sGDIPDLL = @WindowsDir & "\winsxs\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.6000.16386_none_8df21b8362744ace\gdiplus.dll"
		Else
			$sGDIPDLL = "gdiplus.dll"
		EndIf
	EndIf
	$__g_hGDIPDll = DllOpen($sGDIPDLL)
	If $__g_hGDIPDll = -1 Then
		$__g_iGDIPRef = 0
		Return SetError(1, 2, False)
	EndIf
	Local $sVer = FileGetVersion($sGDIPDLL)
	$sVer = StringSplit($sVer, ".")
	If $sVer[1] > 5 Then $__g_bGDIP_V1_0 = False
	Local $tInput = DllStructCreate($tagGDIPSTARTUPINPUT)
	Local $tToken = DllStructCreate("ulong_ptr Data")
	DllStructSetData($tInput, "Version", 1)
	Local $aResult = DllCall($__g_hGDIPDll, "int", "GdiplusStartup", "struct*", $tToken, "struct*", $tInput, "ptr", 0)
	If @error Then Return SetError(@error, @extended, False)
	If $aResult[0] Then Return SetError(10, $aResult[0], False)
	$__g_iGDIPToken = DllStructGetData($tToken, "Data")
	If $bRetDllHandle Then Return $__g_hGDIPDll
	Return True
EndFunc   ;==>_GDIPlus_Startup
Global Const $__SS_BITMAP = 0x0E
Func _SetImage($hWnd, $sImage, $hOverlap = 0)
	$hWnd = _Icons_Control_CheckHandle($hWnd)
	If $hWnd = 0 Then
		Return SetError(1, 0, 0)
	EndIf
	Local $Result, $hImage, $hBitmap, $hFit
	_GDIPlus_Startup()
	$hImage = _GDIPlus_BitmapCreateFromFile($sImage)
	$hFit = _Icons_Control_FitTo($hWnd, $hImage)
	$hBitmap = _GDIPlus_BitmapCreateHBITMAPFromBitmap($hFit)
	_GDIPlus_ImageDispose($hFit)
	_GDIPlus_Shutdown()
	If Not ($hOverlap < 0) Then
		$hOverlap = _Icons_Control_CheckHandle($hOverlap)
	EndIf
	$Result = _Icons_Control_SetImage($hWnd, $hBitmap, 0, $hOverlap)
	If $Result Then
		$hImage = _SendMessage($hWnd, 0x0173, 0, 0)
		If (@error) Or ($hBitmap = $hImage) Then
			$hBitmap = 0
		EndIf
	EndIf
	If $hBitmap Then
		_WinAPI_DeleteObject($hBitmap)
	EndIf
	Return SetError(1 - $Result, 0, $Result)
EndFunc   ;==>_SetImage
Func _Icons_Control_CheckHandle($hWnd)
	If Not IsHWnd($hWnd) Then
		$hWnd = GUICtrlGetHandle($hWnd)
		If $hWnd = 0 Then
			Return 0
		EndIf
	EndIf
	Return $hWnd
EndFunc   ;==>_Icons_Control_CheckHandle
Func _Icons_Control_Enum($hWnd, $iDirection)
	Local $iWnd, $Count = 0, $aWnd[50] = [$hWnd]
	If $iDirection Then
		$iDirection = 2
	Else
		$iDirection = 3
	EndIf
	While 1
		$iWnd = _WinAPI_GetWindow($aWnd[$Count], $iDirection)
		If Not $iWnd Then
			ExitLoop
		EndIf
		$Count += 1
		If $Count = UBound($aWnd) Then
			ReDim $aWnd[$Count + 50]
		EndIf
		$aWnd[$Count] = $iWnd
	WEnd
	ReDim $aWnd[$Count + 1]
	Return $aWnd
EndFunc   ;==>_Icons_Control_Enum
Func _Icons_Control_FitTo($hWnd, $hImage)
	Local $Size = _Icons_Control_GetSize($hWnd)
	If $Size = 0 Then
		Return SetError(1, 0, $hImage)
	EndIf
	_GDIPlus_Startup()
	Local $Width = _GDIPlus_ImageGetWidth($hImage), $Height = _GDIPlus_ImageGetHeight($hImage)
	Local $Ret, $Error = 0
	If ($Width = -1) Or ($Height = -1) Then
		$Error = 1
	Else
		If ($Width <> $Size[0]) Or ($Height <> $Size[1]) Then
			$Ret = DllCall($__g_hGDIPDll, 'int', 'GdipGetImageThumbnail', 'ptr', $hImage, 'int', $Size[0], 'int', $Size[1], 'ptr*', 0, 'ptr', 0, 'ptr', 0)
			If (Not @error) And ($Ret[0] = 0) Then
				_GDIPlus_ImageDispose($hImage)
				$hImage = $Ret[4]
			Else
				$Error = 1
			EndIf
		EndIf
	EndIf
	_GDIPlus_Shutdown()
	Return SetError($Error, 0, $hImage)
EndFunc   ;==>_Icons_Control_FitTo
Func _Icons_Control_GetRect($hWnd)
	Local $Pos = ControlGetPos($hWnd, '', '')
	If (@error) Or ($Pos[2] = 0) Or ($Pos[3] = 0) Then
		Return 0
	EndIf
	Local $tRect = DllStructCreate($tagRECT)
	DllStructSetData($tRect, 1, $Pos[0])
	DllStructSetData($tRect, 2, $Pos[1])
	DllStructSetData($tRect, 3, $Pos[0] + $Pos[2])
	DllStructSetData($tRect, 4, $Pos[1] + $Pos[3])
	Return $tRect
EndFunc   ;==>_Icons_Control_GetRect
Func _Icons_Control_GetSize($hWnd)
	Local $tRect = DllStructCreate($tagRECT)
	Local $Ret = DllCall('user32.dll', 'int', 'GetClientRect', 'hwnd', $hWnd, 'ptr', DllStructGetPtr($tRect))
	If (@error) Or ($Ret[0] = 0) Then
		Return 0
	EndIf
	Local $Size[2] = [DllStructGetData($tRect, 3) - DllStructGetData($tRect, 1), DllStructGetData($tRect, 4) - DllStructGetData($tRect, 2)]
	If ($Size[0] = 0) Or ($Size[1] = 0) Then
		Return 0
	EndIf
	Return $Size
EndFunc   ;==>_Icons_Control_GetSize
Func _Icons_Control_Invalidate($hWnd)
	Local $tRect = _Icons_Control_GetRect($hWnd)
	If IsDllStruct($tRect) Then
		_WinAPI_InvalidateRect(_WinAPI_GetParent($hWnd), $tRect)
	EndIf
EndFunc   ;==>_Icons_Control_Invalidate
Func _Icons_Control_SetImage($hWnd, $hImage, $iType, $hOverlap)
	Local $Static, $Style, $Update, $tRect, $hPrev
	Switch $iType
		Case 0
			$Static = $__SS_BITMAP
		Case 1
			$Static = 0x03
		Case Else
			Return 0
	EndSwitch
	$Style = _WinAPI_GetWindowLong($hWnd, $GWL_STYLE)
	If @error Then
		Return 0
	EndIf
	_WinAPI_SetWindowLong($hWnd, $GWL_STYLE, BitOR($Style, $Static))
	If @error Then
		Return 0
	EndIf
	$tRect = _Icons_Control_GetRect($hWnd)
	$hPrev = _SendMessage($hWnd, 0x0172, $iType, $hImage)
	If @error Then
		Return 0
	EndIf
	If $hPrev Then
		If $iType = 0 Then
			_WinAPI_DeleteObject($hPrev)
		Else
			_WinAPI_DestroyIcon($hPrev)
		EndIf
	EndIf
	If (Not $hImage) And (IsDllStruct($tRect)) Then
		_WinAPI_MoveWindow($hWnd, DllStructGetData($tRect, 1), DllStructGetData($tRect, 2), DllStructGetData($tRect, 3) - DllStructGetData($tRect, 1), DllStructGetData($tRect, 4) - DllStructGetData($tRect, 2), 0)
	EndIf
	If $hOverlap Then
		If Not IsHWnd($hOverlap) Then
			$hOverlap = 0
		EndIf
		_Icons_Control_Update($hWnd, $hOverlap)
	Else
		_Icons_Control_Invalidate($hWnd)
	EndIf
	Return 1
EndFunc   ;==>_Icons_Control_SetImage
Func _Icons_Control_Update($hWnd, $hOverlap)
	Local $tBack, $tFront = _Icons_Control_GetRect($hWnd)
	If $tFront = 0 Then
		Return
	EndIf
	Local $aNext = _Icons_Control_Enum($hWnd, 1)
	Local $aPrev = _Icons_Control_Enum($hWnd, 0)
	If UBound($aPrev) = 1 Then
		_WinAPI_InvalidateRect(_WinAPI_GetParent($hWnd), $tFront)
		Return
	EndIf
	Local $aWnd[UBound($aNext) + UBound($aPrev - 1)]
	Local $tIntersect = DllStructCreate($tagRECT), $pIntersect = DllStructGetPtr($tIntersect)
	Local $iWnd, $Ret, $XOffset, $YOffset, $Count = 0, $Update = 0
	For $i = UBound($aPrev) - 1 To 1 Step -1
		$aWnd[$Count] = $aPrev[$i]
		$Count += 1
	Next
	For $i = 0 To UBound($aNext) - 1
		$aWnd[$Count] = $aNext[$i]
		$Count += 1
	Next
	For $i = 0 To $Count - 1
		If $aWnd[$i] = $hWnd Then
			_WinAPI_InvalidateRect($hWnd)
		Else
			If (Not $hOverlap) Or ($aWnd[$i] = $hOverlap) Then
				$tBack = _Icons_Control_GetRect($aWnd[$i])
				$Ret = DllCall('user32.dll', 'int', 'IntersectRect', 'ptr', $pIntersect, 'ptr', DllStructGetPtr($tFront), 'ptr', DllStructGetPtr($tBack))
				If (Not @error) And ($Ret[0]) Then
					$Ret = DllCall('user32.dll', 'int', 'IsRectEmpty', 'ptr', $pIntersect)
					If (Not @error) And (Not $Ret[0]) Then
						$XOffset = DllStructGetData($tBack, 1)
						$YOffset = DllStructGetData($tBack, 2)
						$Ret = DllCall('user32.dll', 'int', 'OffsetRect', 'ptr', $pIntersect, 'int', -$XOffset, 'int', -$YOffset)
						If (Not @error) And ($Ret[0]) Then
							_WinAPI_InvalidateRect($aWnd[$i], $tIntersect)
							$Update += 1
						EndIf
					EndIf
				EndIf
			EndIf
		EndIf
	Next
	If Not $Update Then
		_WinAPI_InvalidateRect(_WinAPI_GetParent($hWnd), $tFront)
	EndIf
EndFunc   ;==>_Icons_Control_Update
