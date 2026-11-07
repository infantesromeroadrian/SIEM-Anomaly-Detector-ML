# Test fixtures

`access_log_sample.txt` and `auth_log_sample.txt` contain a few lines copied verbatim from the
AIT Log Data Set V2.0 (scenario russellmitchell, `intranet_server`), Landauer et al.,
https://doi.org/10.5281/zenodo.5789064, license CC BY-NC-SA 4.0. Hostnames and addresses are the
dataset's own synthetic testbed values. The iptables line in `test_parsers.py` is hand-written
(the dataset subset used here has no firewall log on this host).
