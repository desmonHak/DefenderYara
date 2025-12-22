
rule Trojan_Win32_Emotet_BAA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f7 8d 3c 08 33 f7 2b d6 05 ?? ?? ?? ?? 83 6d fc 01 75 ?? 8b 45 08 5f 89 10 89 48 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}