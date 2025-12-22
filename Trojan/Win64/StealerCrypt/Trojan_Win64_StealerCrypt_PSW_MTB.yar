
rule Trojan_Win64_StealerCrypt_PSW_MTB{
	meta:
		description = "Trojan:Win64/StealerCrypt.PSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 8d 04 17 41 3b c5 73 56 48 8d 44 06 10 41 8b d2 0f b6 54 17 10 30 10 41 ff c2 44 3b d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}