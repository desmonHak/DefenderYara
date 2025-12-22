
rule Trojan_BAT_Evilnum_PGE_MTB{
	meta:
		description = "Trojan:BAT/Evilnum.PGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 6f 1c 00 00 0a 6f ?? 00 00 0a 26 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 00 09 16 09 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 17 13 05 2b d0 } //10
		$a_03_1 = {0a 09 08 6f ?? 00 00 0a 6f ?? 00 00 0a 26 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 09 16 09 6f ?? 00 00 0a 6f ?? 00 00 0a 26 2b d6 08 2c 06 08 6f ?? 00 00 0a dc } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}