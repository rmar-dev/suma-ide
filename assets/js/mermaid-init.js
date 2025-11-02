// Initialize Mermaid for rendering diagrams
document.addEventListener('DOMContentLoaded', function() {
  // Configure Mermaid
  mermaid.initialize({
    startOnLoad: true,
    theme: 'default',
    themeVariables: {
      primaryColor: '#7253ed',
      primaryTextColor: '#fff',
      primaryBorderColor: '#5e41d0',
      lineColor: '#5e41d0',
      secondaryColor: '#eeebff',
      tertiaryColor: '#fff'
    },
    securityLevel: 'loose',
    flowchart: {
      useMaxWidth: true,
      htmlLabels: true,
      curve: 'basis'
    },
    sequence: {
      useMaxWidth: true,
      showSequenceNumbers: true
    },
    gantt: {
      useMaxWidth: true,
      fontSize: 11
    }
  });

  // Find all mermaid code blocks and render them
  document.querySelectorAll('pre.language-mermaid').forEach(function(element) {
    var code = element.querySelector('code');
    if (code) {
      var mermaidDiv = document.createElement('div');
      mermaidDiv.className = 'mermaid';
      mermaidDiv.textContent = code.textContent;
      element.parentNode.replaceChild(mermaidDiv, element);
    }
  });

  // Re-run Mermaid after initial setup
  mermaid.init(undefined, document.querySelectorAll('.mermaid'));
});
