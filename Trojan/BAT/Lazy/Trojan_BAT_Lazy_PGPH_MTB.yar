
rule Trojan_BAT_Lazy_PGPH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PGPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 12 04 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0c } //5
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 2e 68 6f 72 73 65 2f 6a 73 2f 62 77 5f 62 75 6e 64 6c 65 2e 6a 73 } //https://discord.horse/js/bw_bundle.js  5
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}