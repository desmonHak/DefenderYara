
rule Trojan_BAT_NjRat_SLCB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.SLCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 1e 00 00 0a 20 70 11 01 00 28 1f 00 00 0a 72 01 00 00 70 28 20 00 00 0a 0a 28 14 00 00 06 0b 06 07 28 15 00 00 06 0c 08 28 13 00 00 06 de 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}