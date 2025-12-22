
rule Trojan_Win32_Neoreblamy_GPK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 ?? 40 89 45 90 1b 00 83 7d 90 1b 00 ?? 7f 28 6b 45 90 1b 00 ?? 8d 84 05 ?? ?? ?? ?? 8b 4d 90 1b 00 8b 55 90 1b 00 42 42 6b d2 18 8d 94 15 ?? ?? ?? ?? 8b 75 90 1b 00 8b 04 88 89 04 b2 eb cb 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Neoreblamy_GPK_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {6f 61 78 7a 4b 4c 62 46 41 57 50 62 67 51 73 47 78 48 46 } //3 oaxzKLbFAWPbgQsGxHF
		$a_81_1 = {70 52 62 72 56 62 57 4b 6c 4d 6f 51 48 4b 4c 55 69 44 61 6d 7a 58 } //2 pRbrVbWKlMoQHKLUiDamzX
		$a_81_2 = {5a 54 51 6d 76 54 65 4e 7a 48 74 6d 5a 74 44 4b 69 57 52 6b 42 6a 6d 53 68 74 4c 57 4d 76 } //1 ZTQmvTeNzHtmZtDKiWRkBjmShtLWMv
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}