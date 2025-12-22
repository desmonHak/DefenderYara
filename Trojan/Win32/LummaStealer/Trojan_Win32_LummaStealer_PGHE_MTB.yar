
rule Trojan_Win32_LummaStealer_PGHE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 6e 6b 62 69 68 66 62 65 6f 67 61 65 61 6f 65 68 6c 65 66 6e 6b 6f 64 62 65 66 67 70 67 6b 6e 6e } //Snkbihfbeogaeaoehlefnkodbefgpgknn  1
		$a_80_1 = {4d 65 74 61 4d 61 73 6b } //MetaMask  1
		$a_80_2 = {66 68 62 6f 68 69 6d 61 65 6c 62 6f 68 70 6a 62 62 6c 64 63 6e 67 63 6e 61 70 6e 64 6f 64 6a 70 } //fhbohimaelbohpjbbldcngcnapndodjp  1
		$a_80_3 = {42 69 6e 61 6e 63 65 } //Binance  1
		$a_80_4 = {68 6e 66 61 6e 6b 6e 6f 63 66 65 6f 66 62 64 64 67 63 69 6a 6e 6d 68 6e 66 6e 6b 64 6e 61 61 64 } //hnfanknocfeofbddgcijnmhnfnkdnaad  1
		$a_80_5 = {43 6f 69 6e 62 61 73 65 } //Coinbase  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}