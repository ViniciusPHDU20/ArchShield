pkgname=archshield
pkgver=0.1.0
pkgrel=1
pkgdesc="Network traffic analyzer and anomaly detection tool"
arch=("x86_64")
url="https://github.com/yourusername/archshield" # Replace with actual repo
license=("GPL3")
depends=("python" "python-scapy" "python-pandas" "python-matplotlib" "python-scikit-learn" "tk" "python-flask" "python-requests")
source=("$pkgname-$pkgver.tar.gz::https://github.com/yourusername/archshield/archive/v$pkgver.tar.gz") # Replace with actual repo
sha256sums=("SKIP") # Replace with actual checksum

build() {
  cd "$pkgname-$pkgver"
  # No build steps needed for a Python script
}

package() {
  cd "$pkgname-$pkgver"

  install -D -m755 no_gui_archshield.py "$pkgdir/usr/bin/archshield"
  install -D -m644 archshield.conf "$pkgdir/etc/archshield.conf"
  install -D -m644 archshield.service "$pkgdir/etc/systemd/system/archshield.service"
  install -D -m644 templates/index.html "$pkgdir/usr/share/archshield/templates/index.html"
  install -D -m644 allowed_services.txt "$pkgdir/etc/archshield/allowed_services.txt"

  # Create log directory
  mkdir -p "$pkgdir/var/log/archshield"
  touch "$pkgdir/var/log/archshield/archshield.log"
  chmod 644 "$pkgdir/var/log/archshield/archshield.log"
}


