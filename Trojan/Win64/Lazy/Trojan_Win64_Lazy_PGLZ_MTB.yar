
rule Trojan_Win64_Lazy_PGLZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c2 32 01 32 84 24 ?? ?? ?? ?? 41 32 02 32 07 41 88 04 2f 48 8b c1 81 fb ?? ?? ?? ?? 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}