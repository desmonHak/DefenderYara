
rule Trojan_Win32_Tepfer_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ff 89 db 8b 45 10 8b 55 dc 8b 4d e0 8a 8c 8d ?? ?? ?? ?? 32 4d e7 88 0c 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}