
rule Trojan_Win32_SpyAgent_AMTB{
	meta:
		description = "Trojan:Win32/SpyAgent!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 2e 4f 70 65 6e 28 22 50 4f 53 54 22 2c 20 22 68 74 74 70 3a 2f 2f 7a 78 2e 70 65 2f 62 70 2e 70 68 70 22 2c 20 66 61 6c 73 65 29 } //1 http.Open("POST", "http://zx.pe/bp.php", false)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}