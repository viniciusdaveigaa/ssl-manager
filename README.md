# SSL Manager — Gerenciador de KeyStores (.JKS / .PFX) e Certificados Digitais

Aplicativo desktop **open-source** para Windows (**100% offline/local** e **sem dependência de Java instalado**), desenvolvido para facilitar a criação, leitura, conversão e manutenção de arquivos **Java KeyStore (`.jks` / `cacerts`)** e **PKCS#12 (`.pfx` / `.p12`)**.

Substitui ferramentas tradicionais como *KeyStore Explorer* e *Portecle* com uma interface moderna, direta e focada nas tarefas reais do dia a dia.

---

## Principais Funcionalidades

- **Abrir e editar arquivos `.JKS`, `cacerts` e `.PFX` (`.p12`)** (com ou sem senha).
- **Criar uma nova `.JKS` do zero** definindo a senha inicial.
- **Inserir certificados diretamente na `.JKS`:**
  - Suporta certificados completos **`.PFX` / `.P12`** (chave privada + certificado + cadeia) e certificados públicos **`.CRT`, `.CER`, `.PEM`, `.DER`, `.P7B`**.
  - Permite definir o *Alias* e substituir automaticamente entradas antigas de mesmo nome.
- **Montar arquivo `.PFX` a partir de arquivos separados (`.crt` + `.key`):**
  - Ideal para quando o cliente ou certificadora envia o certificado (`.crt`/`.cer`/`.pem`), a **Private Key** (`.key`) e a cadeia certificadora (`.ca-bundle`) separados.
  - Valida matematicamente na hora se a **Private Key** corresponde ao **Certificado**.
  - Ordena automaticamente a cadeia de certificação (Certificado Principal $\rightarrow$ Intermediárias $\rightarrow$ Raiz) e permite inserir o `.PFX` gerado direto na `.JKS` aberta.
- **Inspeção completa do Certificado:**
  - Exibe titular (*Common Name*), emissor, validade, status de expiração, algoritmo da chave pública, impressões digitais (`SHA-256` e `SHA-1`), domínios cobertos (`SAN`), árvore da cadeia de certificação, conteúdo `PEM` e metadados **ICP-Brasil** (*e-CNPJ* / *e-CPF*).
- **Extração de Kit SSL:**
  - Extrai de qualquer entrada o certificado público (`.crt`), a chave privada desencriptada (`.key`), a cadeia (`.ca-bundle.crt`) e o arquivo concatenado (`-fullchain.pem`).
- **Alta Performance:**
  - Abre e salva KeyStores grandes (como o `cacerts` do Java com mais de 140 certificados) instantaneamente, com ordenação por qualquer coluna e reordenação de colunas via *drag-and-drop*.

---

## Como Usar (Passo a Passo)

### 1. Abrir ou Criar uma `.JKS`
1. Clique em **Abrir .JKS / .PFX** no menu lateral (ou arraste o arquivo para dentro da janela) e informe a senha (ou deixe em branco caso o arquivo não tenha senha).
2. Ou clique em **Criar Nova .JKS** para iniciar uma KeyStore limpa em memória.
3. Caso queira fechar o arquivo atual e limpar a tela a qualquer momento, clique em **Limpar Selecionado** no canto superior direito.

### 2. Inserir um Certificado na `.JKS`
1. Com uma `.JKS` selecionada, o botão **Inserir certificado na .JKS** ficará habilitado.
2. Clique nele e escolha o arquivo do certificado (`.pfx`, `.p12`, `.crt`, `.cer`, `.pem`) no Windows Explorer.
3. Digite a senha do certificado (caso seja `.pfx`/`.p12`), confira a validação do titular e a data de vencimento, defina o **Alias** e confirme.

### 3. Montar um `.PFX` quando o cliente envia `.CRT` + `.KEY` separados
1. Clique em **Montar .PFX (.crt + .key)** no menu lateral.
2. Selecione o **Certificado Principal** (`.crt`/`.cer`/`.pem`) e a **Private Key** (`.key`). O aplicativo indicará imediatamente se o par é válido.
3. Opcionalmente, adicione os certificados intermediários/cadeia.
4. Defina a senha do novo `.PFX`, escolha onde salvar e marque a opção para já inseri-lo automaticamente na `.JKS` aberta, se desejar.

### 4. Salvar a `.JKS` Alterada
1. Clique em **Salvar .JKS Alterada**.
2. Escolha o local do arquivo `.jks` e informe (ou altere) a senha da KeyStore com confirmação de senha.

---

## Como Executar

### Opção 1 — Executável Único (`SSLManager.exe`)
Basta executar o arquivo **`SSLManager.exe`** (não requer instalação de Python nem de Java). Você pode copiar apenas o `SSLManager.exe` para qualquer outro computador com Windows 10/11 (64 bits).

### Opção 2 — Executar a partir do Código-Fonte (Python 3.10+)

1. Crie e ative um ambiente virtual:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   ```
2. Instale as dependências:
   ```powershell
   pip install -r requirements.txt
   ```
3. Inicie a aplicação:
   ```powershell
   python main.py
   ```

---

## Como Compilar o Executável (`SSLManager.exe`)

Para gerar novamente o executável único otimizado com tela de carregamento nativa (*Splash Screen*), execute:

```powershell
.\gerar_executavel.bat
```

---

## Estrutura do Projeto

```text
├── assets/
│   └── app_icon.ico          # Ícone multi-resolução da aplicação
├── core/
│   ├── branding.py           # Nome da aplicação e renderização vetorial do ícone
│   ├── crypto_engine.py      # Motor criptográfico (JKS, PKCS#12, X.509, PEM, ICP-Brasil)
│   ├── icons.py              # Renderizador de ícones vetoriais da interface
│   └── models.py             # Modelos de dados (KeyStoreDocument, KeyStoreEntry, CertificateDetails)
├── ui/
│   ├── main_window.py        # Janela principal, tabela ordenável e ações de KeyStore
│   └── dialogs.py            # Diálogos (Senha, Inserir Certificado, Montar PFX, Extrair, Detalhes)
├── launcher.cs               # Launcher nativo em C# com Splash Screen e cache automático
├── main.py                   # Ponto de entrada da aplicação PyQt6
├── requirements.txt          # Dependências Python (PyQt6, cryptography, pyjks)
├── SSLManager.spec           # Especificação otimizada do PyInstaller
└── test_crypto_engine.py     # Testes automatizados do fluxo criptográfico
```

---

## Licença

Distribuído sob a licença **MIT**. Sinta-se livre para usar, modificar e distribuir.
