
rule Trojan_Win64_NukeSped_AKLB_MTB{
	meta:
		description = "Trojan:Win64/NukeSped.AKLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b d9 48 83 7b 40 40 72 ?? 48 8b cb e8 ?? ?? ?? ?? 48 89 6b 40 48 8b 43 40 48 ff c7 0f b6 0c 18 30 4f ff 48 ff 43 40 48 ff ce 75 } //5
		$a_03_1 = {49 2b fe 49 8b de 49 2b f6 66 0f 1f 44 00 00 48 8d 8d 30 02 00 00 e8 ?? ?? ?? ?? 8b 85 34 22 00 00 33 04 1e 89 03 48 8d 5b 04 48 8d 04 1f 48 3d 10 4b 02 00 76 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}