
rule Trojan_Win32_Woool_GVB_MTB{
	meta:
		description = "Trojan:Win32/Woool.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fe c0 49 66 ff c9 83 c6 01 f8 66 0f be c9 30 c3 80 d5 3e f5 d2 dd 0f b6 c0 66 0f be c8 8b 0c 85 ?? ?? ?? ?? f9 f7 d9 f6 c2 3c f5 88 14 24 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}