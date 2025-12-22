
rule Trojan_Win64_IcedID_ZXT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 fb 48 8b 44 24 ?? 42 8a 04 18 29 ca 01 ea 44 01 ca 01 fa 29 ca 01 fa 44 29 ca 44 29 c2 29 ca 01 ea 44 01 ca 01 fa 29 ca 01 d7 48 8d 15 ?? ?? ?? ?? 44 29 cf 44 29 c7 48 63 ff 32 04 3a 43 88 04 2c e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}