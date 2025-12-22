
rule Trojan_Win64_InterlockRat_CD_MTB{
	meta:
		description = "Trojan:Win64/InterlockRat.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 39 d8 5b 75 ?? 48 c7 c0 01 00 00 00 c3 48 83 f8 00 0f 84 ?? ?? 00 00 ff e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}