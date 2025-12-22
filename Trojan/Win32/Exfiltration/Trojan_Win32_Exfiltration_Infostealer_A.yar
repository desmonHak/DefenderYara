
rule Trojan_Win32_Exfiltration_Infostealer_A{
	meta:
		description = "Trojan:Win32/Exfiltration.Infostealer.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 66 00 6f 00 73 00 74 00 65 00 61 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 infostealer.exe
		$a_00_1 = {66 00 69 00 6c 00 65 00 73 00 5f 00 74 00 6f 00 5f 00 73 00 74 00 65 00 61 00 6c 00 2e 00 74 00 78 00 74 00 } //1 files_to_steal.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}