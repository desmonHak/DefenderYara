
rule Trojan_Win32_Mint_AI_MTB{
	meta:
		description = "Trojan:Win32/Mint.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 89 45 c0 b9 7f 40 00 00 66 89 4d c2 c6 45 c4 8a c6 45 c5 f5 c6 45 c6 0d c6 45 c7 f3 c6 45 c8 5a c6 45 c9 00 c6 45 ca 5c c6 45 cb c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}