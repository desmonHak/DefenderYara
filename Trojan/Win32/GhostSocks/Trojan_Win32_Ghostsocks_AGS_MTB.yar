
rule Trojan_Win32_Ghostsocks_AGS_MTB{
	meta:
		description = "Trojan:Win32/Ghostsocks.AGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 3c b2 0f b6 3f 89 3c b0 8d 6e 01 39 cd 7d ?? 89 ee c1 e5 02 39 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}