
rule Trojan_Win64_XLoader_ACIB_MTB{
	meta:
		description = "Trojan:Win64/XLoader.ACIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d1 48 8d 44 10 10 0f b6 00 48 8b 4d c0 30 01 8b 45 d4 ff c0 89 45 d4 8b 45 d4 3b 45 f4 0f 9c c0 0f b6 c0 89 45 d0 83 7d d0 00 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}