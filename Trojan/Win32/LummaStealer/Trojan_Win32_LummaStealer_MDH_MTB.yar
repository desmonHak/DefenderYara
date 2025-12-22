
rule Trojan_Win32_LummaStealer_MDH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 05 00 00 00 e9 71 fe ff ff 8b 0d 00 51 46 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}