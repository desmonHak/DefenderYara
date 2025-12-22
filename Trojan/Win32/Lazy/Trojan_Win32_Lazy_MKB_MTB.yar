
rule Trojan_Win32_Lazy_MKB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a d1 2a d3 88 13 8d 43 01 89 85 00 af ff ff 8b c7 99 f7 bd 00 af ff ff 89 85 a0 ae ff ff 3b f3 } //15
		$a_01_1 = {0f b7 95 18 af ff ff 03 95 f0 ae ff ff 2b c6 03 85 a8 ae ff ff 0f b6 f9 03 85 a0 ae ff ff 0f b6 cb 03 f9 3b d7 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}