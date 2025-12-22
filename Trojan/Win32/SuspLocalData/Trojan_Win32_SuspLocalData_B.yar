
rule Trojan_Win32_SuspLocalData_B{
	meta:
		description = "Trojan:Win32/SuspLocalData.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_80_0 = {6e 65 74 73 74 61 74 2e 65 78 65 20 2d 6e 61 } //netstat.exe -na  1
		$a_80_1 = {69 70 63 6f 6e 66 69 67 2e 65 78 65 20 2f 64 69 73 70 6c 61 79 64 6e 73 } //ipconfig.exe /displaydns  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}