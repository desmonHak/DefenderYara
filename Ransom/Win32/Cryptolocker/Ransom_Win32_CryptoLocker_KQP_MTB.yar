
rule Ransom_Win32_CryptoLocker_KQP_MTB{
	meta:
		description = "Ransom:Win32/CryptoLocker.KQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 0f 43 75 20 83 bd 24 ff ff ff 08 0f 43 8d 10 ff ff ff 33 d2 f7 b5 20 ff ff ff 66 8b 04 51 8d 8d e0 fe ff ff 66 33 04 7e 0f b7 c0 50 6a 01 e8 ?? ?? ?? ?? 47 3b 7d 30 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}