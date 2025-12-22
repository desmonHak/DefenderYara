
rule Trojan_BAT_NjRat_SLCN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.SLCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 bb 02 00 70 02 28 0d 00 00 06 03 17 18 8d 01 00 00 01 0a 06 16 72 2d 03 00 70 28 1e 00 00 06 a2 06 17 72 9b 03 00 70 28 1e 00 00 06 a2 06 28 32 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}