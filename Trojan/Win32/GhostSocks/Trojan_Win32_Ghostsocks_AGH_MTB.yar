
rule Trojan_Win32_Ghostsocks_AGH_MTB{
	meta:
		description = "Trojan:Win32/Ghostsocks.AGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 03 83 c2 30 66 89 56 14 33 d2 0f b7 47 02 f7 f3 b8 cd ?? ?? ?? 83 c2 30 66 89 56 16 0f b7 4f 06 f7 e1 c1 ea 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}