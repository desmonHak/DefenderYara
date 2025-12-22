
rule Trojan_BAT_OrcusRat_AOR_MTB{
	meta:
		description = "Trojan:BAT/OrcusRat.AOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 25 19 1f 25 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a a2 25 1a 72 ?? 0b 00 70 a2 25 1b 7e ?? 00 00 04 a2 25 1c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}