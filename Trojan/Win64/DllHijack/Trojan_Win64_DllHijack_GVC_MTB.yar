
rule Trojan_Win64_DllHijack_GVC_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 8b c0 48 8b 4d f8 48 c1 e1 05 48 8b 55 f8 48 c1 ea 02 48 33 ca 48 33 c1 48 89 45 f8 8b 45 f4 ff c0 89 45 f4 8b 45 f4 3b 45 28 0f 9c c0 0f b6 c0 89 45 f0 83 7d f0 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}