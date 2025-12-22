
rule Trojan_BAT_Coatimundis_A{
	meta:
		description = "Trojan:BAT/Coatimundis.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 56 48 44 2e 64 6c 6c 00 6b 65 72 6e 65 6c 33 32 ?? 6d 73 63 6f 72 6c 69 62 00 } //1
		$a_01_1 = {76 68 64 00 5c 56 48 44 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}