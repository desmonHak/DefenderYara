
rule Trojan_Win32_Zbot_MR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 8b 95 30 ce ff ff 52 8b 85 a0 cf ff ff 50 ff 95 ec cd ff ff } //10
		$a_01_1 = {8b c8 0f b7 85 c4 fc ff ff 03 05 20 89 42 00 8b 35 20 89 42 00 83 c6 01 99 f7 fe 03 c8 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}