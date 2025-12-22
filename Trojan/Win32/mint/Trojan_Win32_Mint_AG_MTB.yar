
rule Trojan_Win32_Mint_AG_MTB{
	meta:
		description = "Trojan:Win32/Mint.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 83 ec 20 31 c0 89 45 ee 89 45 ea 89 45 e0 64 a1 30 00 00 00 8b 40 08 89 45 ee 8b 45 ee 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}