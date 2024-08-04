import { describe, expect, it } from 'vitest'

import { fromHex, toHex } from '../../encoding/hex.mts'
import { md5, md5Hasher } from '../md5.mts'

const strToMd5: Record<string, Uint8Array> = {
	'': fromHex('d41d8cd98f00b204e9800998ecf8427e'),
	' ': fromHex('7215ee9c7d9dc229d2921a40e899ec5f'),
	'  ': fromHex('23b58def11b45727d3351702515f86af'),
	'   ': fromHex('628631f07321b22d8c176c200c855e1b'),
	'    ': fromHex('0cf31b2c283ce3431794586df7b0996d'),
	hello: fromHex('5d41402abc4b2a76b9719d911017c592'),
	'Hello World!': fromHex('ed076287532e86365e841e92bfc50d8c'),
	'message digest': fromHex('f96b697d7cb7938d525a2f31aaf161d0'),
	'The quick brown fox jumps over the lazy dog': fromHex(
		'9e107d9d372bb6826bd81d3542a419d6',
	),
	'The quick brown fox jumps over the lazy dog.': fromHex(
		'e4d909c290d0fb1ca068ffaddf22cbd0',
	),
	a: fromHex('0cc175b9c0f1b6a831c399e269772661'),
	abc: fromHex('900150983cd24fb0d6963f7d28e17f72'),
	abcdefghijklmnopqrstuvwxyz: fromHex('c3fcd3d76192e4007dfb496cca67e13b'),
	ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789: fromHex(
		'd174ab98d277d9f5a5611c2c9f419d9f',
	),
	'1': fromHex('c4ca4238a0b923820dcc509a6f75849b'),
	'12': fromHex('c20ad4d76fe97759aa27a0c99bff6710'),
	'123': fromHex('202cb962ac59075b964b07152d234b70'),
	'1234': fromHex('81dc9bdb52d04dc20036dbd8313ed055'),
	'12345': fromHex('827ccb0eea8a706c4c34a16891f84e7b'),
	'123456': fromHex('e10adc3949ba59abbe56e057f20f883e'),
	'1234567': fromHex('fcea920f7412b5da7be0cf42b8c93759'),
	'12345678': fromHex('25d55ad283aa400af464c76d713c07ad'),
	'123456789': fromHex('25f9e794323b453885f5181f1b624d0b'),
	'1234567890': fromHex('e807f1fcf82d132f9bb018ca6738a19f'),
	'1234567890a': fromHex('b50d979457eca75e16f9f7c0f6321747'),
	'1234567890ab': fromHex('5aab4fe20e4e90534028b2db43175a34'),
	'1234567890abc': fromHex('43287ae11fca6e336459a32845e41b24'),
	'1234567890abcd': fromHex('3d2a4a6fbf62bd4e9722540718a93917'),
	'1234567890abcde': fromHex('5801c332b4e5ba9c0a297d60bb51cc72'),
	'1234567890abcdef': fromHex('996ce17f6abc9fe126b57aa5f1d8c92c'),
	'12345678901234567890123456789012345678901234567890123456789012345678901234567890':
		fromHex('57edf4a22be3c955ac49da2e2107b67a'),
}

const binSeqUpTo = (length: number): Uint8Array => {
	return new Uint8Array(Array.from({ length }, (_, i) => i + 1))
}

const binaryToMd5: Record<string, Uint8Array> = {
	// All zeros
	['00'.repeat(1)]: fromHex('93b885adfe0da089cdf634904fd59f71'),
	['00'.repeat(2)]: fromHex('c4103f122d27677c9db144cae1394a66'),
	['00'.repeat(3)]: fromHex('693e9af84d3dfcc71e640e005bdc5e2e'),
	['00'.repeat(4)]: fromHex('f1d3ff8443297732862df21dc4e57262'),
	['00'.repeat(5)]: fromHex('ca9c491ac66b2c62500882e93f3719a8'),
	['00'.repeat(6)]: fromHex('7319468847d7b1aee40dbf5dd963c999'),
	['00'.repeat(7)]: fromHex('d310a40483f9399dd7ed1712e0fdd702'),
	['00'.repeat(8)]: fromHex('7dea362b3fac8e00956a4952a3d4f474'),
	['00'.repeat(9)]: fromHex('3f2829b2ffe8434d67f98a2a98968652'),
	['00'.repeat(10)]: fromHex('a63c90cc3684ad8b0a2176a6a8fe9005'),
	['00'.repeat(11)]: fromHex('74da4121dc1c0ed2a8e5b0741f824034'),
	['00'.repeat(12)]: fromHex('8dd6bb7329a71449b0a1b292b5999164'),
	['00'.repeat(13)]: fromHex('0b867e53c1d233ce9fe49d54549a2323'),
	['00'.repeat(14)]: fromHex('36df9540a5ef4996a9737657e4a8929c'),
	['00'.repeat(15)]: fromHex('3449c9e5e332f1dbb81505cd739fbf3f'),
	['00'.repeat(16)]: fromHex('4ae71336e44bf9bf79d2752e234818a5'),
	['00'.repeat(17)]: fromHex('f3c8bdb6b9df478f227af2ce61c8a5a1'),
	['00'.repeat(18)]: fromHex('ff035bff2dcf972ee7dfd023455997ef'),
	['00'.repeat(19)]: fromHex('0e6bce6899fae841f79024afbdf7db1d'),
	['00'.repeat(20)]: fromHex('441018525208457705bf09a8ee3c1093'),
	['00'.repeat(21)]: fromHex('2319ac34f4848755a639fd524038dfd3'),
	['00'.repeat(22)]: fromHex('db46e81649d6863b16bd99ab139c865b'),
	['00'.repeat(23)]: fromHex('6b43b583e2b662724b6fbb5189f6ab28'),
	['00'.repeat(24)]: fromHex('1681ffc6e046c7af98c9e6c232a3fe0a'),
	['00'.repeat(25)]: fromHex('d28c293e10139d5d8f6e4592aeaffc1b'),
	['00'.repeat(26)]: fromHex('a396c59a96af3b36d364448c7b687fb1'),
	['00'.repeat(27)]: fromHex('65435a5d117aa6b052a5f737d9946a7b'),
	['00'.repeat(28)]: fromHex('1c9e99e48a495fe81d388fdb4900e59f'),
	['00'.repeat(29)]: fromHex('4aa476a72347ba44c9bd20c974d0f181'),
	['00'.repeat(30)]: fromHex('862dec5c27142824a394bc6464928f48'),
	['00'.repeat(31)]: fromHex('3861facee9efc127e340387f1936b8fb'),
	['00'.repeat(32)]: fromHex('70bc8f4b72a86921468bf8e8441dce51'),
	['00'.repeat(33)]: fromHex('099a150e83972a433492a59c2fbe98e0'),
	['00'.repeat(34)]: fromHex('0b91f1d54f932dc6382dc69f197900cf'),
	['00'.repeat(35)]: fromHex('c54104d7894a1941ca710981da437f9f'),
	['00'.repeat(36)]: fromHex('81684c2e68ade2cd4bf9f2e8a67dd4fe'),
	['00'.repeat(37)]: fromHex('21e2e8fe686ed0003b67d698b1273481'),
	['00'.repeat(38)]: fromHex('f3a534d52e3fe0c7a85b30ca00ca7424'),
	['00'.repeat(39)]: fromHex('002d5910de023eddce8358edf169c07f'),
	['00'.repeat(40)]: fromHex('fd4b38e94292e00251b9f39c47ee5710'),
	['00'.repeat(41)]: fromHex('f5cfd73023c1eedb6b9569736073f1dd'),
	['00'.repeat(42)]: fromHex('c183857770364b05c2011bdebb914ed3'),
	['00'.repeat(43)]: fromHex('aea2fa668453e23c431649801e5ea548'),
	['00'.repeat(44)]: fromHex('3e5ceb07f51a70d9d431714f04c0272f'),
	['00'.repeat(45)]: fromHex('7622214b8536afe7b89b1c6606069b0d'),
	['00'.repeat(46)]: fromHex('d898504a722bff1524134c6ab6a5eaa5'),
	['00'.repeat(47)]: fromHex('0d7db7ff842f89a36b58fa2541de2a6c'),
	['00'.repeat(48)]: fromHex('b203621a65475445e6fcdca717c667b5'),
	['00'.repeat(49)]: fromHex('884bb48a55da67b4812805cb8905277d'),
	['00'.repeat(50)]: fromHex('871bdd96b159c14d15c8d97d9111e9c8'),
	['00'.repeat(51)]: fromHex('e2365bc6a6fbd41287fae648437296fa'),
	['00'.repeat(52)]: fromHex('469aa816010c9c8639a9176f625189af'),
	['00'.repeat(53)]: fromHex('eca0470178275ac94e5de381969ed232'),
	['00'.repeat(54)]: fromHex('8910e6fc12f07a52b796eb55fbf3edda'),
	['00'.repeat(55)]: fromHex('c9ea3314b91c9fd4e38f9432064fd1f2'),
	['00'.repeat(56)]: fromHex('e3c4dd21a9171fd39d208efa09bf7883'),
	['00'.repeat(57)]: fromHex('ab9d8ef2ffa9145d6c325cefa41d5d4e'),
	['00'.repeat(58)]: fromHex('2c1cf4f76fa1cecc0c4737cfd8d95118'),
	['00'.repeat(59)]: fromHex('22031453e4c3a1a0d47b0b97d83d8984'),
	['00'.repeat(60)]: fromHex('a302a771ee0e3127b8950f0a67d17e49'),
	['00'.repeat(61)]: fromHex('e2a482a3896964675811dba0bfde2f0b'),
	['00'.repeat(62)]: fromHex('8d7d1020185f9b09cc22e789887be328'),
	['00'.repeat(63)]: fromHex('65cecfb980d72fde57d175d6ec1c3f64'),

	// All ones
	['ff'.repeat(1)]: fromHex('00594fd4f42ba43fc1ca0427a0576295'),
	['ff'.repeat(2)]: fromHex('ab2a0d28de6b77ffdd6c72afead099ab'),
	['ff'.repeat(3)]: fromHex('8597d4e7e65352a302b63e07bc01a7da'),
	['ff'.repeat(4)]: fromHex('a54f0041a9e15b050f25c463f1db7449'),
	['ff'.repeat(5)]: fromHex('50f20ea370a1130f64409e521154aa68'),
	['ff'.repeat(6)]: fromHex('00b1abd87bad356b90fcdfcb6132c26f'),
	['ff'.repeat(7)]: fromHex('2a0afadb9fd119cf6344fda615e5db79'),
	['ff'.repeat(8)]: fromHex('c2cb56f4c5bf656faca0986e7eba0308'),
	['ff'.repeat(9)]: fromHex('552a34689d9440ccf12b45c68d4e6ec8'),
	['ff'.repeat(10)]: fromHex('97d4c3505dde00c5b6e28c117e221704'),
	['ff'.repeat(11)]: fromHex('dfd842e55479c438397ddc7f33fb655e'),
	['ff'.repeat(12)]: fromHex('c1fa1f22fa36d331be4027e683baad06'),
	['ff'.repeat(13)]: fromHex('de10f91e6355d0d1048a95b865c42bfe'),
	['ff'.repeat(14)]: fromHex('e2b970633d2474c5fec1cc8a61e4feb2'),
	['ff'.repeat(15)]: fromHex('9ddd02276e5c30436e3b530eba05ad6a'),
	['ff'.repeat(16)]: fromHex('8d79cbc9a4ecdde112fc91ba625b13c2'),
	['ff'.repeat(17)]: fromHex('aca625a04c5f4caad0299c8def569073'),
	['ff'.repeat(18)]: fromHex('ec4d9bcf6cff57d39cf43de74b93ddbb'),
	['ff'.repeat(19)]: fromHex('bc13754d40d0ecbd91c20c68706d10c6'),
	['ff'.repeat(20)]: fromHex('0762a515ab26e0a9837fcadbe42f0712'),
	['ff'.repeat(21)]: fromHex('1538d3059abbcc6ad8d785b36b8f2a53'),
	['ff'.repeat(22)]: fromHex('757226036bf0e9484bd12bff9ba0704f'),
	['ff'.repeat(23)]: fromHex('81ce75f5f620e5964e953cf95650682d'),
	['ff'.repeat(24)]: fromHex('cb98701c46073e5a45e0e72cb5de17a1'),
	['ff'.repeat(25)]: fromHex('2841937c35c311e947bee49864b9d295'),
	['ff'.repeat(26)]: fromHex('0c833cc8156a285c814016def77b2658'),
	['ff'.repeat(27)]: fromHex('6da3d4a6d753fdc930bd9cc30e0afff2'),
	['ff'.repeat(28)]: fromHex('83fbbde4e2e2f7277ba64678046a8059'),
	['ff'.repeat(29)]: fromHex('138b4fd5cbdf4ee5a21414e6ca98a532'),
	['ff'.repeat(30)]: fromHex('9e489c7c597142c7c3ac1201c95b54e1'),
	['ff'.repeat(31)]: fromHex('3498b0e2e50d0de1f6c63c5d7e4fac22'),
	['ff'.repeat(32)]: fromHex('0d7dc4266497100e4831f5b31b6b274f'),
	['ff'.repeat(33)]: fromHex('e88afa9026b35aedc4be9d12ad6d417a'),
	['ff'.repeat(34)]: fromHex('6c006fea774da0c27ad903b98dd39bdb'),
	['ff'.repeat(35)]: fromHex('7931dbcaea4eb6e4b12a5e8c2ae31f89'),
	['ff'.repeat(36)]: fromHex('19317008e3605621e53c4686a32d1448'),
	['ff'.repeat(37)]: fromHex('8cecdc0fccebe76dec28bed5af1b0e52'),
	['ff'.repeat(38)]: fromHex('22ea82234ff4b6025ac1ae830aa05929'),
	['ff'.repeat(39)]: fromHex('9b8b45334fc27e0e6538a6a32fa9bdd2'),
	['ff'.repeat(40)]: fromHex('5c7191c0bf59f6d17bbe1bb4bf222e6b'),
	['ff'.repeat(41)]: fromHex('351aa2cbf626b9509f2803b9e21ee891'),
	['ff'.repeat(42)]: fromHex('006bd5607ab2c3bc65f6f17a74c47c9b'),
	['ff'.repeat(43)]: fromHex('e29327d58c00216a5cf310d0556b71c6'),
	['ff'.repeat(44)]: fromHex('b559a9dc72dc67a9d145432efe4bee5e'),
	['ff'.repeat(45)]: fromHex('b4b990a2175215e0b38150a527c1e134'),
	['ff'.repeat(46)]: fromHex('610005b4bb77820ec48b0ebc60507ffd'),
	['ff'.repeat(47)]: fromHex('d2771705f397679c4b41acbe8a67c9da'),
	['ff'.repeat(48)]: fromHex('5b53000f4d831a433070f80004262910'),
	['ff'.repeat(49)]: fromHex('0dd3cd72b9f2204162fa50ba9a32d30a'),
	['ff'.repeat(50)]: fromHex('be581b8c27c28a84b5fe49d1cbc831ff'),
	['ff'.repeat(51)]: fromHex('27204d71cb8785efbdd8759bb683fe37'),
	['ff'.repeat(52)]: fromHex('c805c8668e36876d4d7aa2ec987c7a8f'),
	['ff'.repeat(53)]: fromHex('880539f1691041ce797112e3ff28b076'),
	['ff'.repeat(54)]: fromHex('30855eb73c2f88ffc3005b998ca4cd69'),
	['ff'.repeat(55)]: fromHex('fd696aa639acaba9ce0e0964028fbe81'),
	['ff'.repeat(56)]: fromHex('74444b7e7b01632f3277365c8ca35ec2'),
	['ff'.repeat(57)]: fromHex('9d243c4a0a71953f292e01dca1be3587'),
	['ff'.repeat(58)]: fromHex('f857297ff8132513d2a604629308fad3'),
	['ff'.repeat(59)]: fromHex('3523d6acbac279fee49bbf7b42ed774c'),
	['ff'.repeat(60)]: fromHex('a011ab15bd0c1d0ffe4caab3095d3025'),
	['ff'.repeat(61)]: fromHex('d1963d35428d2dbe76b4858e4bb91712'),
	['ff'.repeat(62)]: fromHex('c40ace35651c3af4c1cf7a3f7493862b'),
	['ff'.repeat(63)]: fromHex('2e8381ef75aa4df05c31143466ecc2a8'),

	// Increasing sequence
	[toHex(binSeqUpTo(1))]: fromHex('55a54008ad1ba589aa210d2629c1df41'),
	[toHex(binSeqUpTo(2))]: fromHex('0cb988d042a7f28dd5fe2b55b3f5ac7a'),
	[toHex(binSeqUpTo(3))]: fromHex('5289df737df57326fcdd22597afb1fac'),
	[toHex(binSeqUpTo(4))]: fromHex('08d6c05a21512a79a1dfeb9d2a8f262f'),
	[toHex(binSeqUpTo(5))]: fromHex('7cfdd07889b3295d6a550914ab35e068'),
	[toHex(binSeqUpTo(6))]: fromHex('6ac1e56bc78f031059be7be854522c4c'),
	[toHex(binSeqUpTo(7))]: fromHex('498001217bc632cb158588224d7d23c4'),
	[toHex(binSeqUpTo(8))]: fromHex('0ee0646c1c77d8131cc8f4ee65c7673b'),
	[toHex(binSeqUpTo(9))]: fromHex('8596c1af55b14b7b320112944fcb8536'),
	[toHex(binSeqUpTo(10))]: fromHex('70903e79b7575e3f4e7ffa15c2608ac7'),
	[toHex(binSeqUpTo(11))]: fromHex('3a0a12db5c1e3d4e72822fbfec67e4f6'),
	[toHex(binSeqUpTo(12))]: fromHex('d2bc225f9724ea69812867fc45794a2e'),
	[toHex(binSeqUpTo(13))]: fromHex('b61c83e2cbcad5d96fead7d6b949f2fa'),
	[toHex(binSeqUpTo(14))]: fromHex('bf13fc19e5151ac57d4252e0e0f87abe'),
	[toHex(binSeqUpTo(15))]: fromHex('ab3825d5aeaec5925b05d44beb7ddc7d'),
	[toHex(binSeqUpTo(16))]: fromHex('190c4c105786a2121d85018939108a6c'),
	[toHex(binSeqUpTo(17))]: fromHex('5187e484290250b220c67d5c40eac760'),
	[toHex(binSeqUpTo(18))]: fromHex('0f514b1f70495f72ee834a83866e3a45'),
	[toHex(binSeqUpTo(19))]: fromHex('1a68212b64dfc3cc83a13c427cad7ce0'),
	[toHex(binSeqUpTo(20))]: fromHex('4d5555e067dd97d08fef90959b1510cb'),
	[toHex(binSeqUpTo(21))]: fromHex('5e28425275cf3549645864021282b785'),
	[toHex(binSeqUpTo(22))]: fromHex('b6bb6e607a57190f64de3d77ab72605a'),
	[toHex(binSeqUpTo(23))]: fromHex('1e5fefd2559803a79c49b64b88259a46'),
	[toHex(binSeqUpTo(24))]: fromHex('147e88065f0c9f17a7ae174877e6c233'),
	[toHex(binSeqUpTo(25))]: fromHex('8a5690c97e2b1e44de8a68372e83768e'),
	[toHex(binSeqUpTo(26))]: fromHex('aac57ba66a0af28c3cb943275eb7826a'),
	[toHex(binSeqUpTo(27))]: fromHex('997000a18d739761c235a04a5e96ae52'),
	[toHex(binSeqUpTo(28))]: fromHex('85a47158bbcfe75f4551676784d225ef'),
	[toHex(binSeqUpTo(29))]: fromHex('d45a7ba135eee8f6b8befa75ed7e9a8f'),
	[toHex(binSeqUpTo(30))]: fromHex('7f01935a0ea5b5468f1ca86d8dc8cd18'),
	[toHex(binSeqUpTo(31))]: fromHex('d3896a4978b90f9c4703c09c01050ae7'),
	[toHex(binSeqUpTo(32))]: fromHex('5985331bcec971b262122aa1ca5ad411'),
	[toHex(binSeqUpTo(33))]: fromHex('d41608a6b37022ca41d7b7d32d8a0eac'),
	[toHex(binSeqUpTo(34))]: fromHex('1f5acd0a99d51744d5aa5546b13084e8'),
	[toHex(binSeqUpTo(35))]: fromHex('c3de4479d40456032264b64cd04bf6c9'),
	[toHex(binSeqUpTo(36))]: fromHex('782ed146fb8c5262337f2ad02614f901'),
	[toHex(binSeqUpTo(37))]: fromHex('fb1cff7def1a66537e5829223d5d1990'),
	[toHex(binSeqUpTo(38))]: fromHex('df0eda707a27fa1d32c39e14c767a3b5'),
	[toHex(binSeqUpTo(39))]: fromHex('ee80c58e1edcd4f3af47c075d6fcf611'),
	[toHex(binSeqUpTo(40))]: fromHex('b1e76b9efe511bf70d9aa4cb0c3dafc9'),
	[toHex(binSeqUpTo(41))]: fromHex('de96776362c812ed4c9849f43163e0f8'),
	[toHex(binSeqUpTo(42))]: fromHex('4aca5af2ecbe95f519db9f7e28f0a5b3'),
	[toHex(binSeqUpTo(43))]: fromHex('59b3a3a1f8397ee8ab00a30273697b96'),
	[toHex(binSeqUpTo(44))]: fromHex('6b5489ea8158e3662666a57589bbb470'),
	[toHex(binSeqUpTo(45))]: fromHex('420e9302b1cd405a85710c5337ad48fd'),
	[toHex(binSeqUpTo(46))]: fromHex('6fb7e3c228fd930fbfc18565d99f2569'),
	[toHex(binSeqUpTo(47))]: fromHex('12d07993502c2d4246d04eff37b1a2de'),
	[toHex(binSeqUpTo(48))]: fromHex('8fb7da194de8ac2381e355e6f372e6b2'),
	[toHex(binSeqUpTo(49))]: fromHex('3b46d2728e162374b753c22b0c6647e5'),
	[toHex(binSeqUpTo(50))]: fromHex('f6d51ed601f87577a8fba7469e3238b9'),
	[toHex(binSeqUpTo(51))]: fromHex('4bd2e4e3e93a23b5e48538fe2a488f55'),
	[toHex(binSeqUpTo(52))]: fromHex('1c78fcfddf1850496c5fbd87604f4b05'),
	[toHex(binSeqUpTo(53))]: fromHex('7585135641b67529371990f5d587dc14'),
	[toHex(binSeqUpTo(54))]: fromHex('5be9c52d3e8ae8f85129fc610e3e7bd1'),
	[toHex(binSeqUpTo(55))]: fromHex('b0dfea8a6c34da94d11ac2d6859fdd0b'),
	[toHex(binSeqUpTo(56))]: fromHex('0e948e7f8183ae39d759364fa6d61cd2'),
	[toHex(binSeqUpTo(57))]: fromHex('adc5941735e23599c993d518ae4278de'),
	[toHex(binSeqUpTo(58))]: fromHex('22b0e45c4b035c5cf667c2cee361821e'),
	[toHex(binSeqUpTo(59))]: fromHex('619995880f57cb34ff80902fb434a33f'),
	[toHex(binSeqUpTo(60))]: fromHex('fd3ecf0be5eb7335790ea6e887244579'),
	[toHex(binSeqUpTo(61))]: fromHex('9c40f512fe9b747a269bddb8dbd4b250'),
	[toHex(binSeqUpTo(62))]: fromHex('81676d3786a12f93ae3b6a9773e9a543'),
	[toHex(binSeqUpTo(63))]: fromHex('d41676f6509e0ade859c0040ea4bfdc0'),
	[toHex(binSeqUpTo(64))]: fromHex('50e845bfe6c70fee663ab5500fd0c411'),
}

describe('md5', () => {
	it('returns the correct hash for an empty string', async () => {
		const h1 = new Uint8Array(await md5(new TextEncoder().encode('')))
		expect(h1).toEqual(strToMd5[''])

		const h2 = new Uint8Array(await md5(Buffer.from('')))
		expect(h2).toEqual(strToMd5[''])
	})

	it('returns the correct hash for a collection of strings', async () => {
		for (const [data, expectedHash] of Object.entries(strToMd5)) {
			const h1 = new Uint8Array(await md5(new TextEncoder().encode(data)))
			expect(h1).toEqual(expectedHash)
		}
	})

	it('returns the correct hash for a collection of binary streams', async () => {
		for (const [data, expectedHash] of Object.entries(binaryToMd5)) {
			const h1 = new Uint8Array(await md5(fromHex(data)))
			expect(h1).toEqual(expectedHash)
		}
	})
})

describe('md5Hasher', () => {
	it('returns the same digest independently of how we partition the input data', async () => {
		const data = new Uint8Array(256).fill(23)

		const hasher1 = md5Hasher()
		const h1 = await hasher1.update(data).digest()

		for (let i = 4; i < 192; i += 1) {
			const hasher2 = md5Hasher()
			const h2 = await hasher2
				.update(data.slice(0, i))
				.update(data.slice(i))
				.digest()

			expect(h1).toEqual(h2)
		}
	})
})
