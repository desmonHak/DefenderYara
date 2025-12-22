
rule Trojan_BAT_Ribaj_ARI_MTB{
	meta:
		description = "Trojan:BAT/Ribaj.ARI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 09 13 0d 16 13 0e 2b 23 11 0d 11 0e 9a 13 04 7e ?? 00 00 04 1b 33 02 de 1a 11 04 28 ?? 00 00 06 de 03 26 de 00 11 0e 17 58 13 0e 11 0e 11 0d 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}