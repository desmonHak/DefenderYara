
rule Trojan_BAT_Remcos_AWCB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AWCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 08 16 08 8e 69 28 ?? ?? 00 0a 08 8e 69 17 59 13 11 16 13 12 2b 15 08 11 12 08 11 12 91 06 11 12 07 5d 91 61 9c 11 12 17 58 13 12 11 12 11 11 31 e5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}