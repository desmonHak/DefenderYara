
rule Trojan_Win32_CoronaVirus_A{
	meta:
		description = "Trojan:Win32/CoronaVirus.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 20 } //reg.exe add   1
		$a_80_1 = {61 75 74 6f 63 68 65 63 6b 20 61 75 74 6f 63 68 6b 20 2a } //autocheck autochk *  1
		$a_80_2 = {48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 } //HKLM\SYSTEM\CurrentControlSet\Control\Session Manager  1
		$a_80_3 = {42 6f 6f 74 45 78 65 63 75 74 65 } //BootExecute  1
		$a_80_4 = {20 2f 74 20 52 45 47 5f 4d 55 4c 54 49 5f 53 5a 20 2f 46 20 2f 44 20 } // /t REG_MULTI_SZ /F /D   1
		$a_00_5 = {20 00 2f 00 56 00 20 00 } //1  /V 
		$a_00_6 = {39 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 61 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 6e 00 } //-1 9453e881-26a8-4973-ba2e-76269e901d0n
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*-1) >=6
 
}