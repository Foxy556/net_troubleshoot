<div align="center">

# 🌐 net_troubleshoot

**Diagnóstico completo de conectividade de rede em camadas, do adaptador ao HTTP — com relatório em JSON.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 🇧🇷 Sobre

Ferramenta de linha de comando que roda **uma vez** e devolve o diagnóstico completo de uma
máquina — do cabo ao site. Feita para quem precisa responder rápido a *"a internet está ruim"*
sem decorar duas dezenas de comandos.

Cobre todas as camadas do modelo em camadas:

```
L2  Adaptador de rede      → status, IP, máscara, gateway, MTU
L3  IP / ICMP              → ping de gateway e DNS públicos, rota
L4  TCP / UDP              → portas 53, 80, 443, 445, 3389
L5-7 DNS, HTTP, proxy      → resolução multi-servidor, portais de captiva, hosts file
```

---

## ✨ O que ela verifica

- **Adaptadores** — placa ativa, IPv4/IPv6, gateway padrão, MTU
- **Conectividade** — ping para gateway, `1.1.1.1`, `8.8.8.8`, `8.8.4.4`, `9.9.9.9`
- **DNS** — testa contra Google DNS, Cloudflare, Quad9 e OpenDNS e compara o tempo de resposta
- **HTTP** — portais de conectividade reais (Google `generate_204`, Firefox `detectportal`,
  Microsoft `msftconnecttest`), `google.com.br`, `cloudflare.com`
- **Portas** — DNS, HTTP, HTTPS, SMB, RDP
- **Arquivo `hosts`** — entradas suspeitas ou conflitantes
- **Proxy e rota** — configuração do sistema e saltos até o destino
- **Saida estruturada** — terminal colorido, `--log` para arquivo e `--json` para relatório

---

## 🚀 Uso

```bash
# diagnóstico completo (modo padrão)
python net_troubleshoot.py

# testar um host específico
python net_troubleshoot.py --host exemplo.com.br

# gerar relatório JSON
python net_troubleshoot.py --json relatorio.json

# salvar log em arquivo
python net_troubleshoot.py --log

# tudo junto
python net_troubleshoot.py --host exemplo.com.br --json relatorio.json --log
```

<details>
<summary>Exemplo de saída no terminal</summary>

```
  _   _      _   _____ _      _   ___ ___ _  _ _____ _   _  ___ _____
 | \ | |    /_\ |_   _| |    /_\ / __| __| \| |_   _| | | |/ _ \_   _|
 |  \| |   / _ \  | | | |__ / _ \\__ \ _|| .` | | | | |_| | (_) || |
 |_|\_|__/_/ \_\ |_| |____/_/ \_\___/___|_|\_| |_|  \___/ \___/ |_|
     |___/    T R O U B L E S H O O T   D E   R E D E   v1.0

 [ OK  ] Adaptador ativo - 192.168.1.10
 [ OK  ] Gateway padrao - 192.168.1.1
 [ OK  ] Ping 1.1.1.1 - 12 ms
 [ OK  ] DNS Cloudflare - 18 ms
 [WARN ] Porta RDP (3389) nao respondeu
```

</details>

---

## 📦 Gerando um executável

O projeto já inclui o spec do PyInstaller:

```bash
pip install pyinstaller
pyinstaller NetTroubleshoot.spec
# gera o executável em dist/
```

Útil para distribuir a ferramenta em máquinas sem Python instalado.

---

## 📁 Estrutura

```
net_troubleshoot.py    # ferramenta completa (single file)
NetTroubleshoot.spec   # configuração do PyInstaller
```

---

## 📄 Licença

Distribuído sob a licença [MIT](LICENSE).

---

<div align="center">

**Veja também:** [FlightDesk](https://github.com/Foxy556/FlightDesk) ·
[apontamentos](https://github.com/Foxy556/apontamentos) ·
[Perfil](https://github.com/Foxy556)

</div>
