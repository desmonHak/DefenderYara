
rule Trojan_BAT_Rozena_BAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 0b 00 00 04 11 10 91 13 11 11 11 1f 6c 61 d2 13 11 11 11 1f 56 59 d2 13 11 11 11 66 d2 13 11 11 11 1f 59 59 d2 13 11 11 11 1f 5e 61 d2 13 11 11 0a 11 10 11 11 9c 11 10 17 58 13 10 11 10 7e 0b 00 00 04 8e 69 32 b8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}