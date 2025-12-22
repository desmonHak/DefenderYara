
rule Trojan_Win32_SalatStealer_NC_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 00 b8 00 01 f3 } //2
		$a_01_1 = {ff 96 2c 00 b8 00 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}