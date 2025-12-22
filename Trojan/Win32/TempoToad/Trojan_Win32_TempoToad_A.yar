
rule Trojan_Win32_TempoToad_A{
	meta:
		description = "Trojan:Win32/TempoToad.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 04 68 00 30 00 00 8b ?? ?? ?? ff ff ?? 6a 00 ff ?? ?? ?? ff ff } //1
		$a_02_1 = {6a 40 8b 85 ?? ?? ff ff ?? 8b ?? ?? ?? ff ff ?? ff ?? ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}