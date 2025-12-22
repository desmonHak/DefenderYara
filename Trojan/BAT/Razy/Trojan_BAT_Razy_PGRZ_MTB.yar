
rule Trojan_BAT_Razy_PGRZ_MTB{
	meta:
		description = "Trojan:BAT/Razy.PGRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1d 06 08 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 61 d2 81 ?? 00 00 01 08 17 58 0c 08 06 8e 69 32 dd } //5
		$a_03_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 65 00 64 00 69 00 61 00 5c 00 [0-0f] 2e 00 65 00 78 00 65 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}