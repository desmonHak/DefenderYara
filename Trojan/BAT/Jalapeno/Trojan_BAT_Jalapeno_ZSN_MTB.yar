
rule Trojan_BAT_Jalapeno_ZSN_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 11 05 58 91 07 11 05 91 2e 05 16 13 04 2b 0d 11 05 17 58 13 05 11 05 07 8e 69 32 e2 11 04 2c 07 08 09 6f ?? 00 00 0a 09 17 58 0d 09 06 8e 69 07 8e 69 59 31 c1 02 16 31 5b 02 08 6f ?? 00 00 0a 30 52 08 02 17 59 6f ?? 00 00 0a 07 8e 69 58 13 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}