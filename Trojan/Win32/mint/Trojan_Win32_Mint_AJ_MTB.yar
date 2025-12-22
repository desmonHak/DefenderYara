
rule Trojan_Win32_Mint_AJ_MTB{
	meta:
		description = "Trojan:Win32/Mint.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 81 04 21 f5 89 d7 83 e7 02 89 c3 83 f3 01 01 fb 8b 7c 99 04 89 fb 81 e3 fe ff ff 7f 09 eb d1 eb 83 e7 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}