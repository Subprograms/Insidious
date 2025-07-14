# Detection: T1580.003_S3

**Description:** Detects S3 bucket HEAD (`REST.HEAD.BUCKET`) calls from IP addresses outside the corporate VPC ranges (172.31.0.0/16, 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8).  
**MITRE Technique:** T1580.003 – Obtain Cloud Instance Metadata  
**Severity:** Low

---

## Summary

| Metric                         | Value                        |
|--------------------------------|------------------------------|
| Distinct external IPs          | **1**                        |
| Bucket(s) probed               | **burgerqueen-dev-secrets**  |
| Total HEAD requests            | **2**                        |
| Highest-risk operation         | `HEAD.BUCKET`                |

---

## Events

| 08 Jul 2025 02:55:28 | 192.0.2.10 | REST.HEAD.BUCKET | - | Mozilla/5.0 (Windows NT 10.0; Win64; ... |
| 08 Jul 2025 02:55:32 | 192.0.2.10 | REST.HEAD.BUCKET | - | Mozilla/5.0 (Windows NT 10.0; Win64; ... |

---

### Analyst Notes

* HEAD requests can enumerate bucket existence without revealing contents.

---

### Recommended Actions

1. Restrict `s3:HeadBucket` to known IP ranges or IAM roles.  
2. Enable CloudTrail Data Events for bucket existence checks.  
3. Audit public buckets and validate need for external probing.

---

*Generated on 14 Jul 2025.*  