
rule Trojan_Win32_CryptInject_GA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 0d ?? ?? ?? ?? 41 30 48 fd 41 8d 49 02 f7 e1 41 83 c1 05 c1 ea 03 6b c2 0f 2b c8 41 8d 41 fe 0f b6 8c 0d ?? ?? ?? ?? 41 30 48 fe 3d 77 01 00 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}