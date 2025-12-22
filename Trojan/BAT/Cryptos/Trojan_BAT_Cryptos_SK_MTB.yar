
rule Trojan_BAT_Cryptos_SK_MTB{
	meta:
		description = "Trojan:BAT/Cryptos.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 13 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}