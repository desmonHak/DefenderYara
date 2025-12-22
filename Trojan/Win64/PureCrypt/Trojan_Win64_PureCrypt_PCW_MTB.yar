
rule Trojan_Win64_PureCrypt_PCW_MTB{
	meta:
		description = "Trojan:Win64/PureCrypt.PCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 48 8d b4 24 00 09 00 00 48 89 f2 41 b8 04 01 00 00 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}