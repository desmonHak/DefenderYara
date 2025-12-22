
rule Trojan_Win32_Kalavus_C{
	meta:
		description = "Trojan:Win32/Kalavus.C,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 68 00 74 00 6d 00 } //5 \project1.htm
		$a_00_1 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 55 00 2e 00 74 00 6d 00 70 00 } //5 \Temp\U.tmp
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //2 powershell
		$a_00_3 = {20 00 2d 00 63 00 20 00 77 00 67 00 65 00 74 00 20 00 } //2  -c wget 
		$a_00_4 = {20 00 2d 00 6f 00 20 00 } //2  -o 
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=11
 
}