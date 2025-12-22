
rule Trojan_Win64_CryptInject_MJZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 4d bb 81 f3 62 65 00 00 48 89 4d 95 48 89 55 d0 01 d0 89 4d eb 48 89 05 ?? ?? ?? ?? 31 55 a0 8d 0d ?? ?? ?? ?? 8b 45 f2 4c 8b 4d bf 8b 9d 47 ff ff ff 48 ff 04 24 bb 02 00 00 00 3b 1c 24 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}