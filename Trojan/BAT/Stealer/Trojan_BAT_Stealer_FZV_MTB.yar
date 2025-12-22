
rule Trojan_BAT_Stealer_FZV_MTB{
	meta:
		description = "Trojan:BAT/Stealer.FZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 02 7b 17 00 00 04 02 7b 18 00 00 04 6f ?? 00 00 0a 13 0f 20 01 00 00 00 7e d2 00 00 04 7b 9b 00 00 04 39 0f 00 00 00 26 20 01 00 00 00 38 04 00 00 00 fe 0c 00 00 } //5
		$a_03_1 = {11 01 16 6a 6f ?? 00 00 0a 20 00 00 00 00 7e d2 00 00 04 7b a9 00 00 04 3a cc ff ff ff 26 20 00 00 00 00 38 c1 ff ff ff 00 11 06 6f ?? 00 00 0a 20 01 00 00 00 7e d2 00 00 04 7b 7e 00 00 04 39 a5 ff ff ff 26 20 01 00 00 00 38 9a ff ff ff } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}