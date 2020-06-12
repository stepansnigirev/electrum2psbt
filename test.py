from io import BytesIO
from electrum2psbt import electrumtx

# tiny casino legend goose among master add cry vivid reopen equal miracle

xprvs = [
"Vprv1FsHb7cyRznxdqmgEVLNbS2AhWiewQM5La9R33PSEpX2rf4jjdqkQDsNFDPnZ5e54VXE6aT2uhkcxHyGNB2snu43LLktECHgQjncvrvQ9kE",
"Vprv1FY4HuUC9bxEU612mSQJKhxtYKWNZCFQrRvqJDEndCwWaPivHgzHYyLEAbmQmAaBehDmFKdNoEsfcH6Zzpe1bfdF69yLjuCyACHDFZh4uTC",
"Vprv1FkCq5gqvRJVNxc7gBaJLidPdwsphpjiJisVz52zPpJqUwnb3PtAQ8UtHueuCoWajNqDqp86a6V5HmwyUi9QFK91bZJr4PMVhyKAssxsQSW"
]

xpubs = [
"Vpub5nZKjXfDaNUdXJoU88zxzqgHGYEb6jXyuskCKZRjf6KRh9KWN2fLaiVERPT48okPSrwBJDwYCmswRo8XDAWVAY97wqLcSqXLfTib5nDNL8N",
"Vpub5nE6SKWSHyduMZ2pf64tj7d17M2JiXSKRjXcajH63UjuQsygv5osjTx6Liq5D4uNW7Ari7n93kmAsHEgHY56VJRJZgEAYdDs2r8hEaa6Bix",
"Vpub5nSEyVj64nzAGRduZqEtk8HWCyPks9vct2UHGb5Hp67EKS3Mfnhkad6kU5biGdCpVYQM1KNsGXRKc339bX8x73MnmaoS3bCFopzm41daDc1",
]

xprv = "vprv9KGD6psg4TkpUkfDVgZ8VpnPrVytrLBgid6VuWRZ2XZqvp8kapSC3SG9WjGhp3ed4nPhti4XNPfmBMD6yCA3cyZEskY34ZUtB5Q6AdNTFMY"
xpub = "vpub5YFZWLQZtqK7hEjgbi68rxj8QXpPFnuY5r26htqAas6pocTu8MkSbEadMzgzwxFE7mbUpVDgoaDxnS9VRuoHceEZJ8rQXNp5uozddMLjTCa"

# one input
# tx1 = "45505446ff0002000000000101fda6b0c9916ff9fabf76f59275e2107398954a69c403ec51ace4b8a8840fd74e0000000000fdffffff0213860100000000001600146a4fc477b5b091e2c99851c3abd1f708e2689176a086010000000000160014332c554d77b1c8f97edd74c331c550857a4643bdfeffffffff400d03000000000000000201ff53ff045f1cf60323efc38e80000000be812a55e203888ac8b4b7f477b3f8da96f7b3d775dfb437b7cec6839bfc3bb602ea28907558fe41404a2288e0c41537ddb847128ae95c647709b297cd6c22351500000000c5011b00"
# 3 inputs
tx1 = "45505446ff0002000000000103fda6b0c9916ff9fabf76f59275e2107398954a69c403ec51ace4b8a8840fd74e0000000000fdffffff0cb8ba217841ab7883bdcf427d2ca843cd2c49f97f9b5918e491294b0d02ac670000000000fdffffff796a490996b773e6320f1617ab8c1e5ed71e2dfab2f47e02d0c8cf12d35d4dbd0000000000fdffffff023bc20000000000001600146a4fc477b5b091e2c99851c3abd1f708e26891763057050000000000160014332c554d77b1c8f97edd74c331c550857a4643bdfeffffffff400d03000000000000000201ff53ff045f1cf60323efc38e80000000be812a55e203888ac8b4b7f477b3f8da96f7b3d775dfb437b7cec6839bfc3bb602ea28907558fe41404a2288e0c41537ddb847128ae95c647709b297cd6c22351500000000feffffffffa08601000000000000000201ff53ff045f1cf60323efc38e80000000be812a55e203888ac8b4b7f477b3f8da96f7b3d775dfb437b7cec6839bfc3bb602ea28907558fe41404a2288e0c41537ddb847128ae95c647709b297cd6c22351500000100feffffffffa08601000000000000000201ff53ff045f1cf60323efc38e80000000be812a55e203888ac8b4b7f477b3f8da96f7b3d775dfb437b7cec6839bfc3bb602ea28907558fe41404a2288e0c41537ddb847128ae95c647709b297cd6c22351500000000a8011b00"
f = BytesIO(bytes.fromhex(tx1))
etx = electrumtx.ElectrumTx()
etx.deserialize(f)
print(etx)
b = f.read()
print("Unparsed:", len(b))
print(b.hex())
assert etx.serialize() == bytes.fromhex(tx1)