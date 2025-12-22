
rule Trojan_Win32_DarkKomet_GVA_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f d8 c0 66 0f e5 d1 66 0f dc f0 66 0f f5 ff 66 0f 76 e0 0f fa fb 0f e1 c8 0f 71 f0 03 66 0f d5 c3 66 0f 71 d2 cc 31 34 24 66 0f 69 f1 66 0f fe c9 66 0f fc e8 66 0f e9 ec 0f db c7 66 0f 6a f2 eb 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}