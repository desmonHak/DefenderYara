
rule Trojan_Win32_Tepfer_BAI_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c0 89 f6 87 d2 ?? ?? ?? 8b bd d4 fb ff ff 8b b5 d8 fb ff ff 8b 9d dc fb ff ff 8b e5 5d c2 10 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}