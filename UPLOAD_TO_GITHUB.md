# Manual GitHub Upload Instructions

Target account:

```text
https://github.com/sunilgentyala
```

Recommended repository name:

```text
hwaam-authorization-mesh
```

## Method 1: GitHub web upload

1. Sign in to GitHub.
2. Open `https://github.com/new`.
3. Set the owner to `sunilgentyala`.
4. Enter repository name `hwaam-authorization-mesh`.
5. Add the description:

   ```text
   Mission-bounded authorization mesh for humans, workloads, and AI agents.
   ```

6. Select **Public**.
7. Do not initialize with a README, license, or `.gitignore`, because they are already included.
8. Select **Create repository**.
9. Extract the downloaded ZIP file on your computer.
10. In the empty repository page, select **uploading an existing file**.
11. Drag every extracted file and folder into the upload page.
12. Enter commit message `Initial HWAAM reference implementation`.
13. Select **Commit changes**.

GitHub web upload may be inconvenient for hidden folders such as `.github`. The command-line method below is more reliable.

## Method 2: Git command line

Open PowerShell in the extracted repository folder:

```powershell
git init
git add .
git commit -m "Initial HWAAM reference implementation"
git branch -M main
git remote add origin https://github.com/sunilgentyala/hwaam-authorization-mesh.git
git push -u origin main
```

## Enable GitHub Pages

1. Open the repository.
2. Select **Settings**.
3. Select **Pages**.
4. Under **Build and deployment**, select **GitHub Actions**.
5. Open the **Actions** tab.
6. Run **Deploy GitHub Pages** if it did not start automatically.

Expected site:

```text
https://sunilgentyala.github.io/hwaam-authorization-mesh/
```

## Enable private vulnerability reporting

1. Open **Settings**.
2. Select **Code security and analysis**.
3. Enable **Private vulnerability reporting**.

## Add repository topics

Recommended topics:

```text
authorization
access-control
ai-agents
zero-trust
cybersecurity
policy-as-code
least-privilege
oauth
kubernetes-security
python
```

## Verify after upload

Open the **Actions** tab and confirm:

- CI passes for Python 3.10, 3.11, and 3.12.
- GitHub Pages deployment succeeds.
- The README badges become green.
- The Pages URL opens correctly.
