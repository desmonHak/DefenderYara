
rule Trojan_Win32_CobaltStrike_SUPC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SUPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 40 89 45 f8 83 7d f8 08 7d 24 8b 45 fc 83 e0 01 89 45 f4 8b 45 fc d1 e8 89 45 fc 83 7d f4 00 74 0b 8b 45 fc 35 ?? ?? ?? ?? 89 45 fc eb } //2
		$a_01_1 = {31 00 35 00 34 00 2e 00 33 00 36 00 2e 00 31 00 36 00 31 00 2e 00 38 00 39 00 2f 00 63 00 61 00 6b 00 31 00 36 00 38 00 2e 00 62 00 69 00 6e 00 } //1 154.36.161.89/cak168.bin
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}