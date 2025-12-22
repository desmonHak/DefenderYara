
rule Trojan_Win32_Farfli_AHD_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 45 ec 2a d0 88 14 38 40 3b 45 fc 89 45 ec 72 } //30
		$a_03_1 = {8b 38 03 7d 8c 6a ?? 59 be ?? ?? ?? ?? f3 a5 66 a5 42 83 45 8c ?? 3b 50 ?? 72 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}