
rule Trojan_Win32_SusLocalData_B{
	meta:
		description = "Trojan:Win32/SusLocalData.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_80_0 = {6e 65 74 73 74 61 74 2e 65 78 65 20 2d 6e 61 } //netstat.exe -na  1
		$a_80_1 = {69 70 63 6f 6e 66 69 67 2e 65 78 65 20 2f 64 69 73 70 6c 61 79 64 6e 73 } //ipconfig.exe /displaydns  1
		$a_00_2 = {61 00 34 00 35 00 33 00 65 00 38 00 38 00 31 00 2d 00 32 00 36 00 61 00 38 00 2d 00 34 00 39 00 37 00 33 00 2d 00 62 00 6e 00 32 00 65 00 2d 00 37 00 36 00 32 00 36 00 39 00 65 00 39 00 30 00 31 00 64 00 30 00 61 00 } //-1 a453e881-26a8-4973-bn2e-76269e901d0a
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=1
 
}