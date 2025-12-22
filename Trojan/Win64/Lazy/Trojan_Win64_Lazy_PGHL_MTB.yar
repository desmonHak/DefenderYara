
rule Trojan_Win64_Lazy_PGHL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 ff c0 f9 48 85 d5 83 e1 ?? 41 8a 0c 08 66 a9 ?? ?? 30 0a e9 ?? ?? ?? ?? 48 ff c2 3d ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}