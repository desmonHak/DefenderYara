
rule Trojan_Win32_Phorpiex_MX_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 8d 10 fc ff ff 51 8b 95 0c fc ff ff 52 ff 15 c8 20 40 00 89 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}