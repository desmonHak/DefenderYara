
rule Trojan_Win32_ClipBanker_GXF_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 3f 56 ff 76 20 6a 00 6a fd 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 57 6a 00 ff 15 } //5
		$a_03_1 = {6a 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 56 ff 15 ?? ?? ?? ?? 47 03 f6 83 ff 08 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}