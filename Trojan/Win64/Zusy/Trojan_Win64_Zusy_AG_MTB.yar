
rule Trojan_Win64_Zusy_AG_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 d0 48 c1 c0 06 48 31 d0 48 89 c2 48 c1 ea 19 48 31 c2 48 89 d0 48 d1 c0 48 31 d0 48 c7 c2 ?? ?? ?? ?? 48 29 c2 48 89 d0 48 d1 c0 31 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}