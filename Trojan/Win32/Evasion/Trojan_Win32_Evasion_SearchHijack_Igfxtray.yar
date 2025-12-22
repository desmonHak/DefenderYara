
rule Trojan_Win32_Evasion_SearchHijack_Igfxtray{
	meta:
		description = "Trojan:Win32/Evasion.SearchHijack.Igfxtray.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 62 00 5f 00 } //1 \sb_
		$a_00_1 = {69 00 67 00 66 00 78 00 74 00 72 00 61 00 79 00 2e 00 65 00 78 00 65 00 } //1 igfxtray.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}