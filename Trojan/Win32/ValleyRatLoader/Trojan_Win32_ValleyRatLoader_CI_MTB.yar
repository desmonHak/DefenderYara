
rule Trojan_Win32_ValleyRatLoader_CI_MTB{
	meta:
		description = "Trojan:Win32/ValleyRatLoader.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f b6 c0 0f b6 44 04 ?? 30 04 0e 46 3b f7 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}