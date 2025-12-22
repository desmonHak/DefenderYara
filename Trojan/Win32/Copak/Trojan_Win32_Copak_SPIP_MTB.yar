
rule Trojan_Win32_Copak_SPIP_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c2 12 97 e5 c7 31 38 81 c1 df ff ba ad 81 c2 ed c7 ed c7 81 c0 02 00 00 00 81 ea cb 0b 38 3c 81 c1 01 00 00 00 81 e9 10 f3 a5 21 39 f0 7c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}