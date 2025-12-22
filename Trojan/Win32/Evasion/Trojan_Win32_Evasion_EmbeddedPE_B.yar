
rule Trojan_Win32_Evasion_EmbeddedPE_B{
	meta:
		description = "Trojan:Win32/Evasion.EmbeddedPE.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 62 00 5f 00 } //1 sb_
		$a_00_1 = {62 00 64 00 61 00 74 00 61 00 5f 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 65 00 78 00 65 00 } //1 bdata_payload.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}