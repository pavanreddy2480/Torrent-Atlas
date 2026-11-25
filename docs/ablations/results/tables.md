### combined

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| shipped | 163.9 | 157-166 | 1.31 | 135.0 | 5/5 |
| base64 only | 422.5 | 352-441 | 0.28 | 90.1 | 5/5 |
| threads=16 only | 224.5 | 191-226 | 1.58 | 135.1 | 5/5 |
| base64 + 16 threads | 520.9 | 506-533 | 0.34 | 90.1 | 5/5 |
| base64 + 16 threads + 2 MiB pieces | 504.4 | 379-516 | 0.36 | 89.9 | 5/5 |

### combined_wan5ms

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| shipped | 100.2 | 97-102 | 1.32 | 135.0 | 3/3 |
| base64 only | 158.4 | 157-166 | 0.33 | 90.1 | 3/3 |
| threads=16 only | 191.4 | 189-195 | 1.60 | 135.1 | 3/3 |
| base64 + 16 threads | 315.7 | 284-323 | 0.36 | 90.1 | 3/3 |
| base64 + 16 threads + 2 MiB pieces | 395.2 | 390-396 | 0.37 | 89.9 | 3/3 |

### encoding

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| hex (shipped) | 165.5 | 136-167 | 1.29 | 135.0 | 5/5 |
| base64 | 381.7 | 279-440 | 0.27 | 90.1 | 5/5 |

### encryption

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| aes-gcm (shipped) | 164.7 | 162-167 | 1.30 | 135.0 | 5/5 |
| plaintext | 166.3 | 162-170 | 1.28 | 135.0 | 5/5 |

### encryption_base64

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| aes-gcm (shipped) | 419.1 | 401-449 | 0.28 | 90.1 | 5/5 |
| plaintext | 408.5 | 379-482 | 0.26 | 90.1 | 5/5 |

### final_verify

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| full-file sha1 (shipped) | 162.2 | 159-164 | 1.29 | 135.0 | 5/5 |
| no final check | 162.1 | 126-166 | 1.30 | 135.0 | 5/5 |

### final_verify_base64

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| full-file sha1 (shipped) | 413.2 | 402-462 | 0.28 | 90.1 | 5/5 |
| no final check | 408.1 | 361-483 | 0.27 | 90.1 | 5/5 |

### piece_size

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| 64 KiB | 144.2 | 144-148 | 1.38 | 136.3 | 5/5 |
| 128 KiB | 148.2 | 146-157 | 1.34 | 135.7 | 5/5 |
| 256 KiB | 155.1 | 140-157 | 1.31 | 135.2 | 5/5 |
| 512 KiB | 162.1 | 152-167 | 1.30 | 135.0 | 5/5 |
| 1024 KiB | 163.4 | 139-173 | 1.30 | 134.9 | 5/5 |
| 2048 KiB | 156.5 | 144-164 | 1.30 | 134.8 | 5/5 |
| 4096 KiB | 165.2 | 143-171 | 1.30 | 134.8 | 5/5 |

### piece_size_wan5ms

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| 64 KiB | 26.7 | 26-27 | 2.10 | 136.3 | 3/3 |
| 128 KiB | 47.3 | 47-48 | 1.45 | 135.7 | 3/3 |
| 256 KiB | 74.1 | 70-75 | 1.35 | 135.2 | 3/3 |
| 512 KiB | 98.6 | 98-99 | 1.35 | 135.0 | 3/3 |
| 1024 KiB | 120.8 | 119-123 | 1.31 | 134.9 | 3/3 |
| 2048 KiB | 139.4 | 133-140 | 1.32 | 134.8 | 3/3 |
| 4096 KiB | 143.3 | 140-144 | 1.37 | 134.8 | 3/3 |

### piece_verify

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| sha1 per piece (shipped) | 161.3 | 148-165 | 1.30 | 135.0 | 5/5 |
| no piece check | 168.6 | 166-172 | 1.27 | 135.0 | 5/5 |

### piece_verify_base64

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| sha1 per piece (shipped) | 423.7 | 418-439 | 0.27 | 90.1 | 5/5 |
| no piece check | 421.0 | 374-457 | 0.25 | 90.1 | 5/5 |

### selection

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| rarest-first (shipped) | 160.4 | 153-167 | 1.39 | 135.0 | 5/5 |
| sequential | 163.8 | 161-168 | 1.30 | 135.0 | 5/5 |
| random | 162.4 | 130-167 | 1.30 | 135.0 | 5/5 |

### threads

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| 1 threads | 52.4 | 52-53 | 1.22 | 135.0 | 5/5 |
| 2 threads | 91.3 | 90-93 | 1.25 | 135.0 | 5/5 |
| 4 threads | 162.9 | 160-166 | 1.30 | 135.0 | 5/5 |
| 8 threads | 219.0 | 209-222 | 1.57 | 135.0 | 5/5 |
| 16 threads | 221.7 | 210-229 | 1.59 | 135.2 | 5/5 |
| 32 threads | 224.7 | 216-226 | 1.58 | 135.5 | 5/5 |

### threads_wan5ms

| variant | MB/s (median) | min-max | CPU s | wire MB | intact |
|---|---|---|---|---|---|
| 1 threads | 30.3 | 30-30 | 1.29 | 135.0 | 3/3 |
| 2 threads | 55.2 | 55-57 | 1.28 | 135.0 | 3/3 |
| 4 threads | 99.0 | 98-100 | 1.33 | 135.0 | 3/3 |
| 8 threads | 161.6 | 155-166 | 1.49 | 135.0 | 3/3 |
| 16 threads | 190.6 | 183-195 | 1.60 | 135.1 | 3/3 |
| 32 threads | 187.5 | 169-197 | 1.61 | 135.4 | 3/3 |
