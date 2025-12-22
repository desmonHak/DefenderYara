
rule Trojan_Win32_Jaik_MKV_MTB{
	meta:
		description = "Trojan:Win32/Jaik.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 bc 89 45 bc 8b 4d f0 8b 55 d0 8b 04 8a 33 05 ?? ?? ?? ?? 8b 4d f0 8b 55 d0 89 04 8a c7 45 c4 ac 39 00 00 8b 4d c4 83 c1 01 8b 45 c4 99 f7 f9 0f af 45 c4 89 45 c4 8b 55 f0 83 c2 01 89 55 f0 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}