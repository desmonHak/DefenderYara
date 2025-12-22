
rule Trojan_BAT_Rhadamanthys_PF_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {9e 06 06 09 94 06 11 04 94 58 20 ?? ?? ?? ?? 5d 94 13 08 11 06 11 07 7e ?? ?? ?? ?? 02 11 07 91 11 08 61 28 ?? ?? ?? ?? 9c 00 11 07 17 58 13 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}