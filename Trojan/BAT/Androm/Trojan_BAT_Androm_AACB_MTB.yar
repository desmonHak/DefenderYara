
rule Trojan_BAT_Androm_AACB_MTB{
	meta:
		description = "Trojan:BAT/Androm.AACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 91 02 28 ?? 00 00 06 61 d2 0c 7e ?? 00 00 04 08 6f ?? 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}