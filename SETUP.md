# Setup Instructions for ricmar-dev/suma-ide

## Step 1: Create GitHub Repository

1. Go to **https://github.com/new**
2. Fill in:
   - **Repository name**: `suma-ide`
   - **Description**: SUMA IDE Documentation
   - **Visibility**: **Public** (required for free GitHub Pages)
   - **DO NOT** check "Initialize with README"
3. Click **Create repository**

## Step 2: Push Code to GitHub

```bash
cd c:\Users\ricma\Projects\SUMA\gitpages

# Add remote (you're already initialized)
git remote add origin https://github.com/ricmar-dev/suma-ide.git

# Rename branch to main
git branch -M main

# Push to GitHub
git push -u origin main
```

**Alternative with SSH** (if you have SSH keys set up):
```bash
git remote add origin git@github.com:ricmar-dev/suma-ide.git
git branch -M main
git push -u origin main
```

## Step 3: Enable GitHub Pages

1. Go to your repository: **https://github.com/ricmar-dev/suma-ide**
2. Click **Settings** tab
3. Left sidebar > **Pages**
4. Under **Source**, select: **GitHub Actions**
5. Done!

## Step 4: Wait for Deployment

1. Go to **Actions** tab
2. You'll see "Deploy to GitHub Pages" workflow running
3. Wait 2-3 minutes for it to complete
4. Check for green checkmark ✅

## Step 5: Visit Your Site

**Your documentation is now live at:**

🎉 **https://ricmar-dev.github.io/suma-ide/** 🎉

## Troubleshooting

### If push fails with authentication error:

**Option 1: Use Personal Access Token**

1. Go to GitHub > Settings > Developer settings > Personal access tokens > Tokens (classic)
2. Generate new token with `repo` scope
3. When pushing, use token as password:
   ```bash
   git push -u origin main
   # Username: ricmar-dev
   # Password: <paste your token>
   ```

**Option 2: Use GitHub CLI**

```bash
# Install GitHub CLI: https://cli.github.com/
gh auth login
git push -u origin main
```

### If site shows 404:

- Wait 2-3 minutes for first deployment
- Check Actions tab for build status
- Ensure repository is Public

### If Mermaid diagrams don't render:

- Clear browser cache
- Check that pages.yml workflow ran successfully

## Next Steps

- ✅ Site is live
- ⏳ Add more documentation pages
- ⏳ Customize theme (_config.yml)
- ⏳ Add your own content

## Updating Documentation

Just edit files locally and push:

```bash
cd c:\Users\ricma\Projects\SUMA\gitpages

# Edit your files
code index.md

# Commit and push
git add .
git commit -m "Update documentation"
git push origin main

# Site auto-updates in 2-3 minutes!
```

---

**Need help?** Check GitHub Pages docs: https://docs.github.com/en/pages
