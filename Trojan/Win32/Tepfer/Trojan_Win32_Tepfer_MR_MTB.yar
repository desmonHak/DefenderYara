
rule Trojan_Win32_Tepfer_MR_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0 72 } //10
		$a_01_1 = {01 1e 8b 7d d8 03 7d a4 03 fb 03 f8 c7 45 b8 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}