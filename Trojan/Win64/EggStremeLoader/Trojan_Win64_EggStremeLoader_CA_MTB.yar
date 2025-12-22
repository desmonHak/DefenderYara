
rule Trojan_Win64_EggStremeLoader_CA_MTB{
	meta:
		description = "Trojan:Win64/EggStremeLoader.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 48 8d 05 ?? ?? ?? ?? 8a 04 01 34 dd 88 84 0d ?? ?? ?? ?? 48 ff c1 48 83 f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}