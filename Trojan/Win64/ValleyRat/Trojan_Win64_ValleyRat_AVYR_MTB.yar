
rule Trojan_Win64_ValleyRat_AVYR_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.AVYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 01 c0 ff d0 48 8b 54 24 58 48 8b 8c 24 48 05 00 00 48 8b 05 81 1d 01 00 48 01 d0 31 d2 ff d0 48 8b 54 24 58 48 8b 8c 24 50 05 00 00 48 8b 05 96 1d 01 00 48 01 d0 ff d0 48 8b 54 24 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}