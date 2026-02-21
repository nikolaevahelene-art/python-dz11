# Отчет об анализе негативных событий ИБ (BOTSv1)

## 1. Анализ WinEventLog (Security)
|   EventID |   Count | Description                                      |
|----------:|--------:|:-------------------------------------------------|
|      4672 |    7472 | Special privileges assigned to new logon         |
|      4648 |      18 | A logon was attempted using explicit credentials |
|      4625 |       0 | An account failed to log on                      |
|      4720 |       0 | A user account was created                       |

## 2. Анализ DNS логов
### Топ-10 частых DNS запросов
| Domain                                                                             |   Count |
|:-----------------------------------------------------------------------------------|--------:|
| ['demo-01', 'demo-01']                                                             |   25187 |
| unknown                                                                            |   25169 |
| ['kv401-prod.do.dsp.mp.microsoft.com', 'kv401-prod.do.dsp.mp.microsoft.com']       |    4311 |
| ['EJFDEBFEEBFACACACACACACACACACAAA', 'EJFDEBFEEBFACACACACACACACACACAAA']           |    3849 |
| kv401-prod.do.dsp.mp.microsoft.com                                                 |    2976 |
| ['wpad', 'wpad']                                                                   |    2899 |
| ['isatap', 'isatap']                                                               |    2750 |
| ['FHFAEBEECACACACACACACACACACACAAA', 'FHFAEBEECACACACACACACACACACACAAA']           |    2200 |
| ['array405-prod.do.dsp.mp.microsoft.com', 'array405-prod.do.dsp.mp.microsoft.com'] |    1874 |
| array405-prod.do.dsp.mp.microsoft.com                                              |    1443 |

### Подозрительные длинные DNS запросы (возможный туннелинг/DGA)
| query                                                                                                                                                        |   query_len |
|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|------------:|
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |
| ['_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL', '_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.WAYNECORPINC.LOCAL'] |         156 |

## 3. Выводы
- Выявлено использование специальных привилегий (EventID 4672), что характерно для административных действий.
- В DNS логах зафиксированы обращения к различным доменам, включая потенциально аномальные длинные имена.
- В выборке 200к строк WinEventLog не обнаружено неудачных входов (4625), что может быть связано с периодом логов.
