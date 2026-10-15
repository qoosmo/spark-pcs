
### n=20, m=3, threads=1

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random, pair) | 20 | 563 | 944 | 129 | 1669 [1662–1680] | 1.00× | 10.6 | 588170 |
| (t,t+1), pair | 20 | 337 | 943 | 76 | 1367 [1365–1381] | 1.22× | 10.2 | 594218 |
| random, block | 20 | 563 | 436 | 126 | 1137 [1129–1145] | 1.47× | 9.0 | 593418 |
| (t,t+1), block | 20 | 341 | 436 | 70 | 882 [876–889] | 1.89× | 8.4 | 585706 |

### n=20, m=4, threads=1

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random, pair) | 20 | 564 | 864 | 126 | 1567 [1559–1586] | 1.00× | 13.4 | 655682 |
| (t,t+1), pair | 20 | 338 | 865 | 76 | 1305 [1299–1311] | 1.20× | 12.8 | 659618 |
| random, block | 20 | 564 | 294 | 127 | 1001 [997–1007] | 1.57× | 10.6 | 661314 |
| (t,t+1), block | 20 | 338 | 294 | 69 | 738 [731–740] | 2.12× | 9.8 | 658658 |

### n=20, m=3, threads=8

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random, pair) | 20 | 175 | 281 | 38 | 510 [456–554] | 1.00× | 16.7 | 588170 |
| (t,t+1), pair | 20 | 118 | 286 | 27 | 438 [400–487] | 1.16× | 18.1 | 594218 |
| random, block | 20 | 197 | 147 | 40 | 413 [274–457] | 1.24× | 16.7 | 593418 |
| (t,t+1), block | 20 | 112 | 139 | 26 | 323 [219–383] | 1.58× | 15.7 | 585706 |

### n=20, m=4, threads=8

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random, pair) | 20 | 170 | 234 | 34 | 462 [355–506] | 1.00× | 21.6 | 655682 |
| (t,t+1), pair | 20 | 96 | 247 | 21 | 398 [260–429] | 1.16× | 19.7 | 659618 |
| random, block | 20 | 130 | 78 | 38 | 253 [216–345] | 1.83× | 19.3 | 661314 |
| (t,t+1), block | 20 | 86 | 61 | 18 | 176 [160–248] | 2.63× | 15.2 | 658658 |
