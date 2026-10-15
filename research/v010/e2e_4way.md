
### n=20, m=3, threads=1

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random gates, pair leaves) | 40 | 573 | 968 | 132 | 1709 [1692–1801] | 1.00× | 11.0 | 588170 |
| v0.10-rc1 ((t,t+1), pair leaves) | 40 | 341 | 963 | 75 | 1397 [1387–1411] | 1.22× | 10.6 | 594218 |
| random gates, v0.10 leaves | 40 | 568 | 296 | 123 | 1005 [995–1032] | 1.70× | 7.6 | 591242 |
| v0.10 ((t,t+1), keyed group leaves) | 40 | 342 | 296 | 70 | 722 [718–733] | 2.37× | 7.1 | 591562 |

### n=20, m=4, threads=1

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random gates, pair leaves) | 40 | 572 | 892 | 131 | 1622 [1591–1698] | 1.00× | 14.1 | 655682 |
| v0.10-rc1 ((t,t+1), pair leaves) | 40 | 344 | 886 | 77 | 1330 [1318–1359] | 1.22× | 13.4 | 659618 |
| random gates, v0.10 leaves | 40 | 573 | 225 | 124 | 937 [928–961] | 1.73× | 9.8 | 667970 |
| v0.10 ((t,t+1), keyed group leaves) | 40 | 341 | 227 | 70 | 664 [658–673] | 2.44× | 8.8 | 647522 |

### n=20, m=3, threads=8

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random gates, pair leaves) | 40 | 164 | 268 | 38 | 500 [454–549] | 1.00× | 16.9 | 588170 |
| v0.10-rc1 ((t,t+1), pair leaves) | 40 | 113 | 281 | 23 | 431 [327–460] | 1.16× | 17.2 | 594218 |
| random gates, v0.10 leaves | 40 | 141 | 100 | 43 | 318 [211–370] | 1.57× | 14.4 | 591242 |
| v0.10 ((t,t+1), keyed group leaves) | 40 | 91 | 76 | 26 | 201 [162–308] | 2.49× | 14.0 | 591562 |

### n=20, m=4, threads=8

| configuration | N | encode | commit | fold | prover total (IQR) | speedup vs v0.9.1-equiv | verifier | proof bytes |
|---|---|---|---|---|---|---|---|---|
| v0.9.1-equiv (random gates, pair leaves) | 40 | 153 | 240 | 34 | 456 [361–494] | 1.00× | 21.9 | 655682 |
| v0.10-rc1 ((t,t+1), pair leaves) | 40 | 103 | 256 | 23 | 419 [277–445] | 1.09× | 20.3 | 659618 |
| random gates, v0.10 leaves | 40 | 129 | 62 | 40 | 243 [196–315] | 1.88× | 19.0 | 667970 |
| v0.10 ((t,t+1), keyed group leaves) | 40 | 84 | 46 | 18 | 159 [145–186] | 2.87× | 14.3 | 647522 |
