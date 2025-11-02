# Gemfile for GitHub Pages

source "https://rubygems.org"

# GitHub Pages gem (includes Jekyll and plugins)
gem "github-pages", group: :jekyll_plugins

# Just the Docs theme
gem "just-the-docs", "0.8.2"

# Plugins
group :jekyll_plugins do
  gem "jekyll-seo-tag"
  gem "jekyll-github-metadata"
  gem "jekyll-include-cache"
end

# Windows and JRuby does not include zoneinfo files
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

# Performance-booster for watching directories on Windows
gem "wdm", "~> 0.1", :platforms => [:mingw, :x64_mingw, :mswin]

# Lock `http_parser.rb` gem to `v0.6.x` on JRuby builds
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]
