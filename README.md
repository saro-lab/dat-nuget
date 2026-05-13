# DAT - Distributed Access Token

## Document

### [DAT Run Online](https://dat.saro.me)

### [What is DAT](https://dat.saro.me/--/intro)

### [C# Example](https://dat.saro.me/--/libs/nuget-saro-dat)

## support signature algorithm
| name   | algorithm  |
|--------|------------|
| P256   | secp256r1  |
| P384   | secp384r1  |
| P521   | secp521r1  |

## support crypto algorithm
| name       | algorithm                   |
|------------|-----------------------------|
| AES128GCMN | aes-128-gcm n(nonce + body) |
| AES256GCMN | aes-256-cbc n(nonce + body) |


# Performance
- random plain and secure test
- mac mini m4 2024 basic (10 core)
- [BenchTest.cs](Dat.Tests/BenchTest.cs)
```
Plain : UViKg7RdJcd7kHYfjcoFfVVgXqw0So5HopBX0Dl6ClRHc1EHeV9yfhKYEJs3DYabOgKYN3XBIc2LnFz4mGlp6nnavug3UsC1NWAc
Secure : iQfttVVSmonZmafoz7SVOBBkpe3lQ3DAdLXZRfID8GcF15kH0LFnfrLv7WHCaUZx1HiDHhqBcPsMEnZBZud1SdX3yDs6NsojEb7g

Multi-Thread
P256 AES128GCMN Issue * 10000 : 216ms
P256 AES128GCMN Parse * 10000 : 196ms
P256 AES256GCMN Issue * 10000 : 207ms
P256 AES256GCMN Parse * 10000 : 195ms
P384 AES128GCMN Issue * 10000 : 532ms
P384 AES128GCMN Parse * 10000 : 500ms
P384 AES256GCMN Issue * 10000 : 527ms
P384 AES256GCMN Parse * 10000 : 500ms
P521 AES128GCMN Issue * 10000 : 1417ms
P521 AES128GCMN Parse * 10000 : 1483ms
P521 AES256GCMN Issue * 10000 : 1490ms
P521 AES256GCMN Parse * 10000 : 1446ms

Single-Thread
P256 AES128GCMN Issue * 10000 : 903ms
P256 AES128GCMN Parse * 10000 : 802ms
P256 AES256GCMN Issue * 10000 : 870ms
P256 AES256GCMN Parse * 10000 : 800ms
P384 AES128GCMN Issue * 10000 : 2220ms
P384 AES128GCMN Parse * 10000 : 2194ms
P384 AES256GCMN Issue * 10000 : 2223ms
P384 AES256GCMN Parse * 10000 : 2205ms
P521 AES128GCMN Issue * 10000 : 6091ms
P521 AES128GCMN Parse * 10000 : 6048ms
P521 AES256GCMN Issue * 10000 : 6001ms
P521 AES256GCMN Parse * 10000 : 5981ms
```
