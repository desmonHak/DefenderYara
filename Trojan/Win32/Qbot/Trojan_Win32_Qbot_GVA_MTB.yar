
rule Trojan_Win32_Qbot_GVA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 12 03 15 a8 be 48 00 03 c2 8b 15 b8 be 48 00 89 02 6a 00 e8 ?? ?? ?? ?? 8b 15 c8 be 48 00 03 15 f8 be 48 00 03 15 a8 be 48 00 03 c2 8b 15 b8 be 48 00 31 02 83 05 a8 be 48 00 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 05 b8 be 48 00 a1 a8 be 48 00 3b 05 bc be 48 00 72 9a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}