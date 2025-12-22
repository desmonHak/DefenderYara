
rule Trojan_Win32_SuspLocalData_A{
	meta:
		description = "Trojan:Win32/SuspLocalData.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {64 69 72 20 2f 62 20 2f 73 } //dir /b /s  1
		$a_80_2 = {44 65 73 6b 74 6f 70 } //Desktop  1
		$a_80_3 = {66 69 6e 64 73 74 72 20 2f 69 } //findstr /i  1
		$a_80_4 = {77 61 6c 6c 65 74 } //wallet  1
		$a_80_5 = {70 61 73 73 77 6f 72 64 } //password  1
		$a_80_6 = {63 72 79 70 74 } //crypt  1
		$a_00_7 = {6b 00 65 00 79 00 } //1 key
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}