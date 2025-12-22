
rule Trojan_Win64_Lazy_PGLB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 41 0f b6 c9 ff c0 42 32 0c 12 88 0c 13 44 8b 05 ?? ?? ?? ?? 41 3b c0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}