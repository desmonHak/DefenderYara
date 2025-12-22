
rule Trojan_Win32_SuspSettings_F{
	meta:
		description = "Trojan:Win32/SuspSettings.F,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {47 65 74 2d 57 69 6e 53 79 73 74 65 6d 4c 6f 63 61 6c 65 } //Get-WinSystemLocale  1
		$a_80_2 = {53 65 6c 65 63 74 2d 4f 62 6a 65 63 74 } //Select-Object  1
		$a_80_3 = {4f 45 4d 43 50 } //OEMCP  1
		$a_80_4 = {54 65 78 74 49 6e 66 6f 2e 4f 65 6d 43 6f 64 65 50 61 67 65 } //TextInfo.OemCodePage  1
		$a_80_5 = {54 65 78 74 49 6e 66 6f 2e 41 6e 73 69 43 6f 64 65 50 61 67 65 } //TextInfo.AnsiCodePage  1
		$a_00_6 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 6d 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 77 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2cm2-4a17-98w0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_00_6  & 1)*-1) >=6
 
}