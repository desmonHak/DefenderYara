
rule Trojan_Win32_Emotet_AEM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8b 4c 24 08 81 f1 ?? ?? ?? ?? 89 4c 24 24 8b 4c 24 10 8a 14 01 8b 74 24 0c 88 14 06 83 c0 01 8b 7c 24 14 39 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}