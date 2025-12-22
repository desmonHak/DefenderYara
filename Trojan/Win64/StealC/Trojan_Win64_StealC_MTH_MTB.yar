
rule Trojan_Win64_StealC_MTH_MTB{
	meta:
		description = "Trojan:Win64/StealC.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 7c 3c 18 41 31 f9 46 88 0c 00 49 8d 48 01 48 39 ce 7e 1e 48 89 cf 48 83 e1 f0 49 89 f8 48 29 cf 46 0f b6 0c 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}