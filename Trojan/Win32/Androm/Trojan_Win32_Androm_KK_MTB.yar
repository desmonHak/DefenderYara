
rule Trojan_Win32_Androm_KK_MTB{
	meta:
		description = "Trojan:Win32/Androm.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 19 99 59 f7 f9 80 c2 61 88 54 35 c0 46 83 fe 07 } //10
		$a_01_1 = {68 79 74 72 37 66 69 73 67 66 68 74 72 6f 33 39 } //5 hytr7fisgfhtro39
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}
rule Trojan_Win32_Androm_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 44 61 74 61 40 2d 40 6a 76 72 32 2e 65 78 65 40 2d 40 6a 76 72 } //10 AppData@-@jvr2.exe@-@jvr
		$a_01_1 = {52 65 6d 6f 74 65 48 6f 6f 6b 31 } //1 RemoteHook1
		$a_81_2 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 } //1 REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v
		$a_81_3 = {2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 /t REG_SZ /d
		$a_81_4 = {2d 6e 6f 74 72 61 79 } //1 -notray
		$a_81_5 = {50 65 49 6e 2e 65 78 65 } //1 PeIn.exe
		$a_81_6 = {5c 73 79 73 74 65 6d 33 32 5c 69 70 63 6f 6e 66 69 67 2e 65 78 65 } //1 \system32\ipconfig.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}