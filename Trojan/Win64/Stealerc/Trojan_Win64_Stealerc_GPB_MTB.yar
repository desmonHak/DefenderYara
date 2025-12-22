
rule Trojan_Win64_Stealerc_GPB_MTB{
	meta:
		description = "Trojan:Win64/Stealerc.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c9 66 0f 7f 8c 24 ?? 01 00 00 66 0f 7f 84 24 ?? 01 00 00 66 0f 7f 8c 24 ?? 01 00 00 48 8d 15 bf dc 6b 00 49 8b cf } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}