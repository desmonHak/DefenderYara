
rule Trojan_Win32_Latrodectus_YAD_MTB{
	meta:
		description = "Trojan:Win32/Latrodectus.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c5 89 45 fc c6 85 ?? ?? ?? ?? 55 c6 85 ?? ?? ?? ?? b0 c6 85 ?? ?? ?? ?? 7c c6 85 } //10
		$a_03_1 = {b9 01 00 00 00 69 d1 ?? ?? ?? ?? 8d 8d fc e9 ff ff 0f b6 14 0a 33 c2 b9 01 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}