
rule Trojan_BAT_StealC_IVBN_MTB{
	meta:
		description = "Trojan:BAT/StealC.IVBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1b 12 02 28 ?? 01 00 0a 0d 07 09 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 00 00 0a 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}