
rule Trojan_Win32_Tepfer_EDSM_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.EDSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 10 ff 8b 15 ?? ?? ?? ?? 33 c2 f7 d0 } //2
		$a_03_1 = {5a 88 02 ff 07 4b ?? ?? 5f 5e 5b } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}