
rule Trojan_BAT_Cerbu_SLGB_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.SLGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 fc 00 00 0a 6f 90 00 00 0a 06 07 6f dd 00 00 0a 17 73 93 00 00 0a 0c 08 02 16 02 8e 69 6f 95 00 00 0a 08 6f 97 00 00 0a 06 28 8e 02 00 06 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}