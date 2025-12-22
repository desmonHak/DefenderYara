
rule Trojan_Win32_SuspDisco_C{
	meta:
		description = "Trojan:Win32/SuspDisco.C,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f } //cmd.exe /c echo  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {73 65 63 72 65 74 2e 74 78 74 } //secret.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}