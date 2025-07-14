# Detection: T1595.004_S3

**Description:** Detects S3 object-listing (`REST.GET.BUCKET` with `?list-type=`) calls from IP addresses outside the corporate VPC ranges (172.31.0.0/16, 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8).  
**MITRE Technique:** T1595.004 – Cloud Storage Object Discovery  
**Severity:** Medium

---

## Summary

| Metric                         | Value                           |
|--------------------------------|---------------------------------|
| Distinct external IPs          | **1**     |
| Bucket(s) involved             | **burgerqueen-dev-secrets**          |
| Total list requests            | **2**       |
| Highest-risk operation         | `GET.BUCKET?list-type=`         |

---

## Events

| 07 Jul 2025 02:55:48 | 158.62.32.52 | REST.GET.BUCKET | - | Mozilla/5.0 (Windows NT 10.0; Win64; ... |
| 08 Jul 2025 02:55:52 | 158.62.32.52 | REST.GET.BUCKET | - | python-requests/2.28.1 |

---

### Analyst Notes

* Object-listing calls may expose filenames and directory structures.

---

### Recommended Actions

1. Enforce least-privilege on `s3:ListObjects` and require source IP conditions.  
2. Enable S3 Inventory or Object Lock for critical buckets.  
3. Remove any public-read ACLs or overly permissive policies.

---

*Generated on 14 Jul 2025.*  