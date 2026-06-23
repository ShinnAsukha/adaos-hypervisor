#!/usr/bin/env python3
"""v2.8.1 i18n fill — real translations for the new TR strings (AI chat,
themes, vApp, reports, boot splash, health, QoS, SDN, LB, mTLS, attestation,
telemetry, golden-image marketplace) into en/es/de/zh/fr.

Reads the gap lists produced by i18n_html_scan + i18n_js_scan, verifies every
gap key has a translation here (fails loudly otherwise — no silent EN
fallback), merges into tmp_i18n/{lang}.json → {lang}_full.json, then the
existing i18n_inject.py rewrites all five PAGE_STRINGS blocks.
"""
from __future__ import annotations
import json
import os
import sys

OUT = "tmp_i18n"
LANGS = ("en", "es", "de", "zh", "fr")

# (tr, en, es, de, zh, fr)
ROWS = [
 ('"Gönderilecek Payload" butonuna tıkla', 'Click the "Payload to send" button', 'Haz clic en el botón "Payload a enviar"', 'Auf die Schaltfläche „Zu sendende Payload" klicken', '点击"待发送负载"按钮', 'Cliquez sur le bouton « Charge à envoyer »'),
 ('%40 indirim + tüm güncellemeler', '40% off + all updates', '40% de descuento + todas las actualizaciones', '40% Rabatt + alle Updates', '四折优惠 + 所有更新', '40 % de réduction + toutes les mises à jour'),
 ('(opsiyonel — SSH anahtarı varsa)', '(optional — if an SSH key is set)', '(opcional — si hay clave SSH)', '(optional — falls SSH-Schlüssel vorhanden)', '（可选 — 若已设置 SSH 密钥）', '(optionnel — si une clé SSH est définie)'),
 ("(ör. Windows 11) VM'lerde firmware logosu değiştirilemediğinden gösterilmez. Boot sırasına dokunmaz; sadece YENİ VM'lere uygulanır.", "Not shown on (e.g. Windows 11) VMs because the firmware logo can't be replaced. Does not touch boot order; applies to NEW VMs only.", "No se muestra en VMs (p. ej. Windows 11) porque el logo del firmware no se puede reemplazar. No altera el orden de arranque; solo se aplica a VMs NUEVAS.", "Wird auf (z. B. Windows 11) VMs nicht angezeigt, da das Firmware-Logo nicht ersetzt werden kann. Ändert die Boot-Reihenfolge nicht; gilt nur für NEUE VMs.", "在（例如 Windows 11）虚拟机上不显示，因为固件徽标无法替换。不影响启动顺序；仅应用于新虚拟机。", "Non affiché sur les VM (p. ex. Windows 11) car le logo du firmware ne peut pas être remplacé. N'affecte pas l'ordre de démarrage ; s'applique uniquement aux NOUVELLES VM."),
 ('/ yıl', '/ year', '/ año', '/ Jahr', '/年', '/ an'),
 ('0 = sınırsız. Bir eksende', '0 = unlimited. On one axis', '0 = ilimitado. En un eje', '0 = unbegrenzt. Auf einer Achse', '0 = 无限制。在同一维度上', '0 = illimité. Sur un axe'),
 ('30 GÜN İADE', '30-DAY REFUND', 'REEMBOLSO 30 DÍAS', '30 TAGE RÜCKGABE', '30 天退款', 'REMBOURSEMENT 30 JOURS'),
 ('30 gün koşulsuz iade', '30-day no-questions refund', 'Reembolso sin condiciones de 30 días', '30 Tage Rückgabe ohne Bedingungen', '30 天无条件退款', 'Remboursement sans condition de 30 jours'),
 ('AI Asistan Sohbet', 'AI Assistant Chat', 'Chat del Asistente IA', 'KI-Assistent-Chat', 'AI 助手聊天', 'Chat de l\'assistant IA'),
 ('AI Insight', 'AI Insight', 'Análisis IA', 'KI-Einblick', 'AI 洞察', 'Analyse IA'),
 ('AI ajanı yok.', 'No AI agent.', 'Sin agente IA.', 'Kein KI-Agent.', '无 AI 代理。', 'Aucun agent IA.'),
 ('Anomali + kapasite → öncelikli aksiyon önerileri', 'Anomalies + capacity → prioritized action suggestions', 'Anomalías + capacidad → sugerencias de acción priorizadas', 'Anomalien + Kapazität → priorisierte Handlungsvorschläge', '异常 + 容量 → 优先操作建议', 'Anomalies + capacité → suggestions d\'actions prioritaires'),
 ('Anonim Kullanım Telemetrisi', 'Anonymous Usage Telemetry', 'Telemetría de uso anónima', 'Anonyme Nutzungstelemetrie', '匿名使用遥测', 'Télémétrie d\'usage anonyme'),
 ("Açıkken her yeni VM, herhangi bir OS'tan ÖNCE BIOS POST'ta OXware logosunu gösterir (VMware tarzı). SeaBIOS (varsayılan q35) VM'lerde", 'When enabled, every new VM shows the OXware logo at BIOS POST BEFORE any OS (VMware-style). On SeaBIOS (default q35) VMs', 'Cuando está activo, cada VM nueva muestra el logo de OXware en el POST del BIOS ANTES de cualquier SO (estilo VMware). En VMs SeaBIOS (q35 por defecto)', 'Wenn aktiviert, zeigt jede neue VM das OXware-Logo beim BIOS-POST VOR jedem Betriebssystem (VMware-Stil). Auf SeaBIOS-VMs (Standard q35)', '启用后，每台新虚拟机会在 BIOS POST 阶段、任何操作系统之前显示 OXware 徽标（VMware 风格）。在 SeaBIOS（默认 q35）虚拟机上', 'Une fois activé, chaque nouvelle VM affiche le logo OXware au POST du BIOS AVANT tout OS (style VMware). Sur les VM SeaBIOS (q35 par défaut)'),
 ("Backend'ler (ip:port, virgül)", 'Backends (ip:port, comma)', 'Backends (ip:puerto, coma)', 'Backends (IP:Port, Komma)', '后端 (ip:端口，逗号分隔)', 'Backends (ip:port, virgule)'),
 ('Beklenen servisler (systemd) ve portlar — virgülle ayır. Boş bırakırsan sadece boot + guest-agent kontrol edilir.', 'Expected services (systemd) and ports — comma-separated. If left empty, only boot + guest-agent are checked.', 'Servicios esperados (systemd) y puertos — separados por comas. Si se deja vacío, solo se verifican el arranque + el guest-agent.', 'Erwartete Dienste (systemd) und Ports — kommagetrennt. Leer = nur Boot + Guest-Agent werden geprüft.', '预期服务 (systemd) 和端口 — 逗号分隔。留空则仅检查启动 + guest-agent。', 'Services attendus (systemd) et ports — séparés par des virgules. Si vide, seuls le démarrage + l\'agent invité sont vérifiés.'),
 ('CA Oluştur/Doğrula', 'Create/Verify CA', 'Crear/Verificar CA', 'CA erstellen/prüfen', '创建/验证 CA', 'Créer/Vérifier la CA'),
 ('Devre dışı bırak', 'Disable', 'Desactivar', 'Deaktivieren', '禁用', 'Désactiver'),
 ('Disk I/O QoS:', 'Disk I/O QoS:', 'QoS de E/S de disco:', 'Festplatten-E/A-QoS:', '磁盘 I/O QoS：', 'QoS d\'E/S disque :'),
 ('Disk seç', 'Select disk', 'Selecciona disco', 'Datenträger wählen', '选择磁盘', 'Sélectionner le disque'),
 ('Disk QoS uygulandı', 'Disk QoS applied', 'QoS de disco aplicada', 'Datenträger-QoS angewendet', '磁盘 QoS 已应用', 'QoS disque appliquée'),
 ('EN POPÜLER', 'MOST POPULAR', 'MÁS POPULAR', 'AM BELIEBTESTEN', '最受欢迎', 'LE PLUS POPULAIRE'),
 ('Endpoint (Toplayıcı Adresi)', 'Endpoint (Collector Address)', 'Endpoint (Dirección del recolector)', 'Endpoint (Collector-Adresse)', '端点（收集器地址）', 'Point de terminaison (adresse du collecteur)'),
 ('En az bir üye VM seç', 'Select at least one member VM', 'Selecciona al menos una VM miembro', 'Mindestens eine Mitglieds-VM wählen', '至少选择一台成员虚拟机', 'Sélectionnez au moins une VM membre'),
 ('En fazla 6 görsel', 'Max 6 images', 'Máximo 6 imágenes', 'Maximal 6 Bilder', '最多 6 张图片', '6 images maximum'),
 ('Endpoint boş olamaz', 'Endpoint cannot be empty', 'El endpoint no puede estar vacío', 'Endpoint darf nicht leer sein', '端点不能为空', 'Le point de terminaison ne peut pas être vide'),
 ('Envanter / uyumluluk / maliyet / denetim raporu üret, önizle, gönder (Telegram/Discord/e-posta) veya haftalık zamanla.', 'Generate, preview, send (Telegram/Discord/e-mail) an inventory / compliance / cost / audit report, or schedule it weekly.', 'Genera, previsualiza y envía (Telegram/Discord/correo) un informe de inventario / cumplimiento / costos / auditoría, o prográmalo semanalmente.', 'Inventar-/Compliance-/Kosten-/Audit-Bericht erstellen, vorschauen, senden (Telegram/Discord/E-Mail) oder wöchentlich planen.', '生成、预览、发送（Telegram/Discord/邮件）库存/合规/成本/审计报告，或按周计划。', 'Générez, prévisualisez, envoyez (Telegram/Discord/e-mail) un rapport d\'inventaire / conformité / coût / audit, ou planifiez-le chaque semaine.'),
 ('Export başlatılamadı (qemu-img/virsh?)', 'Could not start export (qemu-img/virsh?)', 'No se pudo iniciar la exportación (¿qemu-img/virsh?)', 'Export konnte nicht gestartet werden (qemu-img/virsh?)', '无法启动导出 (qemu-img/virsh?)', 'Impossible de démarrer l\'export (qemu-img/virsh ?)'),
 ("Federation node'ları arası karşılıklı TLS. Özel CA + node sertifikaları. Paylaşılan token yerine kriptografik kimlik.", 'Mutual TLS between federation nodes. Private CA + node certificates. Cryptographic identity instead of a shared token.', 'TLS mutuo entre nodos de federación. CA privada + certificados de nodo. Identidad criptográfica en vez de un token compartido.', 'Gegenseitiges TLS zwischen Föderationsknoten. Private CA + Knotenzertifikate. Kryptografische Identität statt eines gemeinsamen Tokens.', '联邦节点之间的双向 TLS。私有 CA + 节点证书。用加密身份取代共享令牌。', 'TLS mutuel entre nœuds de fédération. CA privée + certificats de nœud. Identité cryptographique au lieu d\'un jeton partagé.'),
 ('Golden Image Marketplace', 'Golden Image Marketplace', 'Mercado de imágenes golden', 'Golden-Image-Marktplatz', 'Golden Image 市场', 'Place de marché Golden Image'),
 ("Golden Image'dan VM:", 'VM from Golden Image:', 'VM desde imagen golden:', 'VM aus Golden Image:', '从 Golden Image 创建虚拟机：', 'VM depuis une image Golden :'),
 ('Gönderilecek Payload', 'Payload to send', 'Payload a enviar', 'Zu sendende Payload', '待发送负载', 'Charge à envoyer'),
 ('Gönderilecek Payload (Preview)', 'Payload to send (Preview)', 'Payload a enviar (Vista previa)', 'Zu sendende Payload (Vorschau)', '待发送负载（预览）', 'Charge à envoyer (Aperçu)'),
 ('Gönderim Geçmişi (lokal)', 'Send History (local)', 'Historial de envíos (local)', 'Sendeverlauf (lokal)', '发送历史（本地）', 'Historique d\'envoi (local)'),
 ('Gönderilemedi (bildirim kanalı yapılandırıldı mı?)', 'Could not send (is a notification channel configured?)', 'No se pudo enviar (¿hay un canal de notificación configurado?)', 'Senden fehlgeschlagen (ist ein Benachrichtigungskanal konfiguriert?)', '发送失败（是否已配置通知渠道？）', 'Échec de l\'envoi (un canal de notification est-il configuré ?)'),
 ('Görsel ekle', 'Add image', 'Agregar imagen', 'Bild hinzufügen', '添加图片', 'Ajouter une image'),
 ('Görseli Üret', 'Generate image', 'Generar imagen', 'Bild generieren', '生成图片', 'Générer l\'image'),
 ('Görünüm / Tema', 'Appearance / Theme', 'Apariencia / Tema', 'Darstellung / Design', '外观 / 主题', 'Apparence / Thème'),
 ('Havuz Ekle / Güncelle', 'Add / Update Pool', 'Agregar / Actualizar grupo', 'Pool hinzufügen / aktualisieren', '添加 / 更新池', 'Ajouter / Mettre à jour le pool'),
 ("Hazır cloud-init golden image'ları (Ubuntu / Debian / Rocky / Alma) tek tık önbelleğe al, ardından saniyeler içinde çalışır VM oluştur. ISO kurulumu yok — image hazır boot eder, cloud-init ile kullanıcı/parola/SSH otomatik gömülür.", 'Cache ready cloud-init golden images (Ubuntu / Debian / Rocky / Alma) in one click, then create a running VM in seconds. No ISO install — the image boots ready, and cloud-init injects user/password/SSH automatically.', 'Almacena en caché imágenes golden cloud-init (Ubuntu / Debian / Rocky / Alma) con un clic y crea una VM en marcha en segundos. Sin instalación ISO — la imagen arranca lista y cloud-init inyecta usuario/contraseña/SSH automáticamente.', 'Cloud-init-Golden-Images (Ubuntu / Debian / Rocky / Alma) mit einem Klick zwischenspeichern und in Sekunden eine laufende VM erstellen. Keine ISO-Installation — das Image bootet bereit, und cloud-init fügt Benutzer/Passwort/SSH automatisch ein.', '一键缓存现成的 cloud-init golden 镜像（Ubuntu / Debian / Rocky / Alma），数秒内创建可运行的虚拟机。无需 ISO 安装——镜像即开即用，cloud-init 自动注入用户名/密码/SSH。', 'Mettez en cache des images Golden cloud-init prêtes (Ubuntu / Debian / Rocky / Alma) en un clic, puis créez une VM en quelques secondes. Aucune installation ISO — l\'image démarre prête et cloud-init injecte utilisateur/mot de passe/SSH automatiquement.'),
 ('IP, hostname, MAC, kullanıcı adı, email, şifre, VM isimleri, ağ konfigürasyonu, dosya yolları, lisans anahtarı.', 'IP, hostname, MAC, username, email, password, VM names, network configuration, file paths, license key.', 'IP, hostname, MAC, nombre de usuario, correo, contraseña, nombres de VM, configuración de red, rutas de archivo, clave de licencia.', 'IP, Hostname, MAC, Benutzername, E-Mail, Passwort, VM-Namen, Netzwerkkonfiguration, Dateipfade, Lizenzschlüssel.', 'IP、主机名、MAC、用户名、邮箱、密码、虚拟机名称、网络配置、文件路径、许可证密钥。', 'IP, nom d\'hôte, MAC, nom d\'utilisateur, e-mail, mot de passe, noms de VM, configuration réseau, chemins de fichiers, clé de licence.'),
 ('Karbon / Enerji Ayak İzi', 'Carbon / Energy Footprint', 'Huella de carbono / energía', 'CO₂-/Energie-Fußabdruck', '碳 / 能源足迹', 'Empreinte carbone / énergie'),
 ('Kurulum ücreti $0 (normalde $500)', 'Setup fee $0 (normally $500)', 'Cuota de instalación $0 (normalmente $500)', 'Einrichtungsgebühr 0 $ (normalerweise 500 $)', '安装费 $0（通常 $500）', 'Frais d\'installation 0 $ (normalement 500 $)'),
 ("L2-over-L3 overlay ağlar — kiracılar VLAN değişikliği olmadan host'lar arası izole ağ alır. iproute2 (ip link vxlan) gerekir.", 'L2-over-L3 overlay networks — tenants get isolated cross-host networks without VLAN changes. Requires iproute2 (ip link vxlan).', 'Redes overlay L2 sobre L3 — los inquilinos obtienen redes aisladas entre hosts sin cambios de VLAN. Requiere iproute2 (ip link vxlan).', 'L2-über-L3-Overlay-Netzwerke — Mandanten erhalten isolierte hostübergreifende Netzwerke ohne VLAN-Änderungen. Erfordert iproute2 (ip link vxlan).', 'L2-over-L3 覆盖网络——租户无需更改 VLAN 即可获得跨主机隔离网络。需要 iproute2 (ip link vxlan)。', 'Réseaux overlay L2-sur-L3 — les locataires obtiennent des réseaux isolés inter-hôtes sans changement de VLAN. Nécessite iproute2 (ip link vxlan).'),
 ('Mesaj yaz... (Enter gönder, Shift+Enter satır)', 'Type a message... (Enter to send, Shift+Enter for newline)', 'Escribe un mensaje... (Enter para enviar, Shift+Enter para salto de línea)', 'Nachricht schreiben... (Enter zum Senden, Shift+Enter für neue Zeile)', '输入消息……（Enter 发送，Shift+Enter 换行）', 'Écrire un message... (Entrée pour envoyer, Maj+Entrée pour un saut de ligne)'),
 ('Node adı gerekli', 'Node name required', 'Se requiere nombre de nodo', 'Knotenname erforderlich', '需要节点名称', 'Nom de nœud requis'),
 ('Node Sertifikası Ver', 'Issue Node Certificate', 'Emitir certificado de nodo', 'Knotenzertifikat ausstellen', '签发节点证书', 'Émettre un certificat de nœud'),
 ('OVA export başladı...', 'OVA export started...', 'Exportación OVA iniciada...', 'OVA-Export gestartet...', 'OVA 导出已开始……', 'Export OVA démarré...'),
 ('OXY — AI Asistan Sohbet', 'OXY — AI Assistant Chat', 'OXY — Chat del Asistente IA', 'OXY — KI-Assistent-Chat', 'OXY — AI 助手聊天', 'OXY — Chat de l\'assistant IA'),
 ('Olay Özeti (son 12 saat)', 'Event Summary (last 12 hours)', 'Resumen de eventos (últimas 12 horas)', 'Ereigniszusammenfassung (letzte 12 Stunden)', '事件摘要（过去 12 小时）', 'Résumé des événements (12 dernières heures)'),
 ('Overlay Ağları', 'Overlay Networks', 'Redes overlay', 'Overlay-Netzwerke', '覆盖网络', 'Réseaux overlay'),
 ('Overlay oluşturuldu', 'Overlay created', 'Overlay creado', 'Overlay erstellt', '覆盖网络已创建', 'Overlay créé'),
 ('Panel temasını seç. Seçim tarayıcında kaydedilir.', 'Choose the panel theme. Your choice is saved in the browser.', 'Elige el tema del panel. Tu elección se guarda en el navegador.', 'Panel-Design wählen. Die Auswahl wird im Browser gespeichert.', '选择面板主题。选择会保存在浏览器中。', 'Choisissez le thème du panneau. Votre choix est enregistré dans le navigateur.'),
 ('Parola veya SSH anahtarı gerekli', 'Password or SSH key required', 'Se requiere contraseña o clave SSH', 'Passwort oder SSH-Schlüssel erforderlich', '需要密码或 SSH 密钥', 'Mot de passe ou clé SSH requis'),
 ('Periyot (gün)', 'Interval (days)', 'Intervalo (días)', 'Intervall (Tage)', '周期（天）', 'Intervalle (jours)'),
 ('Politikayı Kaydet', 'Save Policy', 'Guardar política', 'Richtlinie speichern', '保存策略', 'Enregistrer la politique'),
 ('Rapor gönderildi: ', 'Report sent: ', 'Informe enviado: ', 'Bericht gesendet: ', '报告已发送：', 'Rapport envoyé : '),
 ('Rapor zamanlandı', 'Report scheduled', 'Informe programado', 'Bericht geplant', '报告已计划', 'Rapport planifié'),
 ('Read IOPS', 'Read IOPS', 'IOPS de lectura', 'Lese-IOPS', '读取 IOPS', 'IOPS en lecture'),
 ('SSH anahtarı gerekli.', 'SSH key required.', 'Se requiere clave SSH.', 'SSH-Schlüssel erforderlich.', '需要 SSH 密钥。', 'Clé SSH requise.'),
 ('Satın Al', 'Buy', 'Comprar', 'Kaufen', '购买', 'Acheter'),
 ('Satış ile İletişim', 'Contact Sales', 'Contactar con ventas', 'Vertrieb kontaktieren', '联系销售', 'Contacter le service commercial'),
 ('Sağlık Analizi', 'Health Analysis', 'Análisis de salud', 'Zustandsanalyse', '健康分析', 'Analyse de santé'),
 ('Sağlık Analizi & Aksiyonlar', 'Health Analysis & Actions', 'Análisis de salud y acciones', 'Zustandsanalyse & Aktionen', '健康分析与操作', 'Analyse de santé et actions'),
 ('Sağlık Kontrolü:', 'Health Check:', 'Comprobación de salud:', 'Zustandsprüfung:', '健康检查：', 'Vérification de santé :'),
 ('Sağlık politikası kaydedildi', 'Health policy saved', 'Política de salud guardada', 'Zustandsrichtlinie gespeichert', '健康策略已保存', 'Politique de santé enregistrée'),
 ('Sistem durumu, kapasite, VM analizi — doğal dilde sor.', 'System status, capacity, VM analysis — ask in natural language.', 'Estado del sistema, capacidad, análisis de VM — pregunta en lenguaje natural.', 'Systemstatus, Kapazität, VM-Analyse — in natürlicher Sprache fragen.', '系统状态、容量、虚拟机分析——用自然语言提问。', 'État du système, capacité, analyse de VM — demandez en langage naturel.'),
 ('Sohbet başlığı', 'Chat title', 'Título del chat', 'Chat-Titel', '聊天标题', 'Titre du chat'),
 ('Sohbet seçin veya yeni başlatın', 'Select a chat or start a new one', 'Selecciona un chat o inicia uno nuevo', 'Chat auswählen oder neuen starten', '选择一个聊天或新建', 'Sélectionnez un chat ou démarrez-en un nouveau'),
 ('Sohbeti sil', 'Delete chat', 'Eliminar chat', 'Chat löschen', '删除聊天', 'Supprimer le chat'),
 ('Son olayların AI özeti', 'AI summary of recent events', 'Resumen IA de eventos recientes', 'KI-Zusammenfassung der letzten Ereignisse', '近期事件的 AI 摘要', 'Résumé IA des événements récents'),
 ('Splash görseli üretildi', 'Splash image generated', 'Imagen de splash generada', 'Splash-Bild generiert', '启动图已生成', 'Image de démarrage générée'),
 ('Stripe güvencesi', 'Stripe assurance', 'Garantía de Stripe', 'Stripe-Sicherheit', 'Stripe 保障', 'Garantie Stripe'),
 ('Sürüm, host OS ailesi (ubuntu/debian), mimari, kernel major, CPU çekirdek sayısı, RAM GB, VM sayısı, node sayısı, aktif feature ID\'leri, ülke kodu (locale).', 'Version, host OS family (ubuntu/debian), architecture, kernel major, CPU core count, RAM GB, VM count, node count, enabled feature IDs, country code (locale).', 'Versión, familia del SO del host (ubuntu/debian), arquitectura, kernel mayor, número de núcleos de CPU, RAM GB, número de VM, número de nodos, IDs de funciones activas, código de país (locale).', 'Version, Host-OS-Familie (ubuntu/debian), Architektur, Kernel-Hauptversion, CPU-Kernanzahl, RAM in GB, VM-Anzahl, Knotenanzahl, aktive Feature-IDs, Ländercode (Locale).', '版本、主机操作系统系列（ubuntu/debian）、架构、内核主版本、CPU 核心数、内存 GB、虚拟机数量、节点数量、已启用功能 ID、国家代码（区域设置）。', 'Version, famille d\'OS hôte (ubuntu/debian), architecture, version majeure du noyau, nombre de cœurs CPU, RAM Go, nombre de VM, nombre de nœuds, IDs de fonctionnalités activées, code pays (locale).'),
 ('Tanıtım Turu', 'Product Tour', 'Tour del producto', 'Produkttour', '产品导览', 'Visite guidée'),
 ('Tek node, sınırsız VM', 'Single node, unlimited VMs', 'Un nodo, VMs ilimitadas', 'Ein Knoten, unbegrenzte VMs', '单节点，无限虚拟机', 'Nœud unique, VM illimitées'),
 ('Telemetrinin gönderileceği adres. Kendi toplayıcını çalıştırıyorsan (örn.', 'Address where telemetry is sent. If you run your own collector (e.g.', 'Dirección a la que se envía la telemetría. Si ejecutas tu propio recolector (p. ej.', 'Adresse, an die Telemetrie gesendet wird. Wenn du einen eigenen Collector betreibst (z. B.', '遥测数据发送的地址。如果你运行自己的收集器（例如', 'Adresse où la télémétrie est envoyée. Si vous exécutez votre propre collecteur (p. ex.'),
 ('Total IOPS', 'Total IOPS', 'IOPS totales', 'Gesamt-IOPS', '总 IOPS', 'IOPS totales'),
 ('Tüm planlar', 'All plans', 'Todos los planes', 'Alle Tarife', '所有方案', 'Tous les forfaits'),
 ('UEFI/Secure-Boot', 'UEFI/Secure-Boot', 'UEFI/Arranque seguro', 'UEFI/Secure Boot', 'UEFI/安全启动', 'UEFI/Secure Boot'),
 ('Uygula (canlı + kalıcı)', 'Apply (live + persistent)', 'Aplicar (en vivo + persistente)', 'Anwenden (live + dauerhaft)', '应用（实时 + 持久）', 'Appliquer (à chaud + persistant)'),
 ('VM Başlat/Durdur', 'Start/Stop VM', 'Iniciar/Detener VM', 'VM starten/stoppen', '启动/停止虚拟机', 'Démarrer/Arrêter la VM'),
 ('VM adı zorunlu', 'VM name is required', 'El nombre de la VM es obligatorio', 'VM-Name ist erforderlich', '虚拟机名称为必填项', 'Le nom de la VM est obligatoire'),
 ('VM oluşturuldu: ', 'VM created: ', 'VM creada: ', 'VM erstellt: ', '虚拟机已创建：', 'VM créée : '),
 ("VM'lerin önüne TCP yük dengeleyici. İzole HAProxy instance'ı (sistem haproxy'sine dokunmaz). Sağlık kontrollü backend havuzları.", 'TCP load balancer in front of VMs. Isolated HAProxy instance (does not touch the system haproxy). Health-checked backend pools.', 'Balanceador de carga TCP delante de las VMs. Instancia HAProxy aislada (no toca el haproxy del sistema). Pools de backend con comprobación de salud.', 'TCP-Lastausgleich vor den VMs. Isolierte HAProxy-Instanz (berührt das System-HAProxy nicht). Backend-Pools mit Zustandsprüfung.', '位于虚拟机前的 TCP 负载均衡器。隔离的 HAProxy 实例（不影响系统 haproxy）。带健康检查的后端池。', 'Équilibreur de charge TCP devant les VM. Instance HAProxy isolée (ne touche pas le haproxy système). Pools de backends avec contrôle de santé.'),
 ('VNI', 'VNI', 'VNI', 'VNI', 'VNI', 'VNI'),
 ("Vault'taki secret çalışan VM içine guest-agent ile yazılır (SSH yok). VM çalışır + guest-agent gerekli.", 'The Vault secret is written into the running VM via the guest agent (no SSH). Requires the VM running + guest agent.', 'El secreto de Vault se escribe dentro de la VM en ejecución mediante el guest agent (sin SSH). Requiere la VM en ejecución + guest agent.', 'Das Vault-Secret wird über den Guest-Agent in die laufende VM geschrieben (kein SSH). Erfordert laufende VM + Guest-Agent.', 'Vault 密钥通过 guest-agent 写入运行中的虚拟机（无需 SSH）。需要虚拟机运行 + guest-agent。', 'Le secret Vault est écrit dans la VM en cours d\'exécution via l\'agent invité (sans SSH). Nécessite la VM démarrée + l\'agent invité.'),
 ('Verilmiş Node\'lar', 'Issued Nodes', 'Nodos emitidos', 'Ausgestellte Knoten', '已签发节点', 'Nœuds émis'),
 ('Write IOPS', 'Write IOPS', 'IOPS de escritura', 'Schreib-IOPS', '写入 IOPS', 'IOPS en écriture'),
 ('Yeni / Güncelle vApp', 'New / Update vApp', 'Nueva / Actualizar vApp', 'Neue / vApp aktualisieren', '新建 / 更新 vApp', 'Nouvelle / Mettre à jour la vApp'),
 ('Yeni Attestation Al', 'Get New Attestation', 'Obtener nueva atestación', 'Neue Attestierung abrufen', '获取新认证', 'Obtenir une nouvelle attestation'),
 ('Yeni Overlay', 'New Overlay', 'Nuevo overlay', 'Neues Overlay', '新建覆盖网络', 'Nouvel overlay'),
 ('Yeni Sohbet', 'New Chat', 'Nuevo chat', 'Neuer Chat', '新建聊天', 'Nouveau chat'),
 ('aynı anda kullanılamaz (libvirt kuralı). IOPS = saniyedeki işlem, bytes/sec = bant.', 'cannot be used at the same time (libvirt rule). IOPS = operations per second, bytes/sec = bandwidth.', 'no se pueden usar a la vez (regla de libvirt). IOPS = operaciones por segundo, bytes/s = ancho de banda.', 'können nicht gleichzeitig verwendet werden (libvirt-Regel). IOPS = Operationen pro Sekunde, Bytes/s = Bandbreite.', '不能同时使用（libvirt 规则）。IOPS = 每秒操作数，bytes/sec = 带宽。', 'ne peuvent pas être utilisés en même temps (règle libvirt). IOPS = opérations par seconde, octets/s = bande passante.'),
 ('başlatma sırası + gecikme', 'start order + delay', 'orden de inicio + retraso', 'Startreihenfolge + Verzögerung', '启动顺序 + 延迟', 'ordre de démarrage + délai'),
 ('cloud-init ile ilk açılışta otomatik gömülür. Parola', 'Injected automatically at first boot via cloud-init. Password', 'Se inyecta automáticamente en el primer arranque mediante cloud-init. Contraseña', 'Wird beim ersten Start automatisch über cloud-init eingefügt. Passwort', '通过 cloud-init 在首次启动时自动注入。密码', 'Injecté automatiquement au premier démarrage via cloud-init. Mot de passe'),
 ('hatası alırsın.', 'you will get an error.', 'obtendrás un error.', 'erhältst du einen Fehler.', '你会收到一个错误。', 'vous obtiendrez une erreur.'),
 ('ile', 'with', 'con', 'mit', '使用', 'avec'),
 ('ile aç/kapat (önce DB, 10sn bekle, sonra app). Kapatma ters sırada. vSphere vApp karşılığı.', 'power on/off with it (DB first, wait 10s, then app). Shutdown in reverse order. The vSphere vApp equivalent.', 'enciende/apaga con esto (primero la BD, espera 10s, luego la app). Apagado en orden inverso. El equivalente a vApp de vSphere.', 'damit ein-/ausschalten (zuerst DB, 10s warten, dann App). Herunterfahren in umgekehrter Reihenfolge. Das vSphere-vApp-Äquivalent.', '据此开机/关机（先数据库，等待 10 秒，再应用）。关机按相反顺序。相当于 vSphere vApp。', 'allumez/éteignez ainsi (BD d\'abord, attendre 10 s, puis l\'app). Arrêt dans l\'ordre inverse. L\'équivalent vApp de vSphere.'),
 ('kullanılır — bu adres yoksa', 'is used — if this address is missing', 'se usa — si esta dirección falta', 'wird verwendet — wenn diese Adresse fehlt', '将被使用——如果此地址缺失', 'est utilisée — si cette adresse est absente'),
 ('sayfasından bir ajan ekleyin (Anthropic/OpenAI/OpenRouter). Her sohbet için ajan seçilebilir.', 'add an agent from the page (Anthropic/OpenAI/OpenRouter). An agent can be chosen per chat.', 'agrega un agente desde la página (Anthropic/OpenAI/OpenRouter). Se puede elegir un agente por chat.', 'füge auf der Seite einen Agenten hinzu (Anthropic/OpenAI/OpenRouter). Pro Chat kann ein Agent gewählt werden.', '在页面中添加一个代理（Anthropic/OpenAI/OpenRouter）。每个聊天可单独选择代理。', 'ajoutez un agent depuis la page (Anthropic/OpenAI/OpenRouter). Un agent peut être choisi par chat.'),
 ('vApp Adı', 'vApp Name', 'Nombre de vApp', 'vApp-Name', 'vApp 名称', 'Nom de la vApp'),
 ('vApp adı gerekli', 'vApp name required', 'Se requiere nombre de vApp', 'vApp-Name erforderlich', '需要 vApp 名称', 'Nom de vApp requis'),
 ('vApp — VM Grupları', 'vApp — VM Groups', 'vApp — Grupos de VM', 'vApp — VM-Gruppen', 'vApp — 虚拟机组', 'vApp — Groupes de VM'),
 ("veya yerel sunucu) URL'ini buraya yaz. Boş bırakırsan varsayılan", 'or a local server) write its URL here. If left empty, the default', 'o un servidor local) escribe su URL aquí. Si se deja vacío, el valor por defecto', 'oder einen lokalen Server) trage hier dessen URL ein. Wenn leer, wird der Standard', '或本地服务器），在此填写其 URL。留空则使用默认', 'ou un serveur local) saisissez son URL ici. Si vide, la valeur par défaut'),
 ('Ömür boyu güncelleme', 'Lifetime updates', 'Actualizaciones de por vida', 'Lebenslange Updates', '终身更新', 'Mises à jour à vie'),
 ('Önce', 'First', 'Primero', 'Zuerst', '首先', 'D\'abord'),
 ('Önce AI ajanı ekleyin', 'Add an AI agent first', 'Primero agrega un agente IA', 'Zuerst einen KI-Agenten hinzufügen', '请先添加 AI 代理', 'Ajoutez d\'abord un agent IA'),
 ('Üye Ekle', 'Add Member', 'Agregar miembro', 'Mitglied hinzufügen', '添加成员', 'Ajouter un membre'),
 ("İsteğe bağlı, varsayılan kapalı, anonim kullanım istatistiği. OXware'i geliştirmek için kaç kişinin kullandığını, hangi sürümleri, hangi özellikleri kullandığını öğrenmemize yardımcı olur.", 'Optional, off by default, anonymous usage statistics. Helps us learn how many people use OXware, which versions and which features, to improve it.', 'Estadísticas de uso anónimas, opcionales y desactivadas por defecto. Nos ayuda a saber cuántas personas usan OXware, qué versiones y qué funciones, para mejorarlo.', 'Optionale, standardmäßig deaktivierte, anonyme Nutzungsstatistik. Hilft uns zu erfahren, wie viele Personen OXware nutzen, welche Versionen und welche Funktionen, um es zu verbessern.', '可选、默认关闭的匿名使用统计。帮助我们了解有多少人使用 OXware、使用哪些版本和功能，以便改进。', 'Statistiques d\'utilisation anonymes, optionnelles et désactivées par défaut. Nous aide à savoir combien de personnes utilisent OXware, quelles versions et quelles fonctionnalités, pour l\'améliorer.'),
 ('Şimdi Gönder', 'Send Now', 'Enviar ahora', 'Jetzt senden', '立即发送', 'Envoyer maintenant'),
 ('Şimdi Gönder (Test)', 'Send Now (Test)', 'Enviar ahora (prueba)', 'Jetzt senden (Test)', '立即发送（测试）', 'Envoyer maintenant (test)'),
 ('Telemetri etkinleştirildi. İlk ping arka planda atılacak.', 'Telemetry enabled. The first ping will be sent in the background.', 'Telemetría activada. El primer ping se enviará en segundo plano.', 'Telemetrie aktiviert. Der erste Ping wird im Hintergrund gesendet.', '遥测已启用。首次 ping 将在后台发送。', 'Télémétrie activée. Le premier ping sera envoyé en arrière-plan.'),
 ('Telemetri kapatıldı.', 'Telemetry disabled.', 'Telemetría desactivada.', 'Telemetrie deaktiviert.', '遥测已关闭。', 'Télémétrie désactivée.'),
 ('İndirme başladı: ', 'Download started: ', 'Descarga iniciada: ', 'Download gestartet: ', '下载已开始：', 'Téléchargement démarré : '),
 ('— açık kaynak, kendin doğrula.', '— open source, verify it yourself.', '— código abierto, verifícalo tú mismo.', '— Open Source, überprüfe es selbst.', '— 开源，你可以自行验证。', '— open source, vérifiez par vous-même.'),
 ('— fw_cfg + boot menüsü ile.', '— via fw_cfg + boot menu.', '— mediante fw_cfg + menú de arranque.', '— über fw_cfg + Boot-Menü.', '— 通过 fw_cfg + 启动菜单。', '— via fw_cfg + menu de démarrage.'),
 # v2.8.1 — Ağ Modu & IP tespiti + sekme grupları
 ('Ağ Modu & IP', 'Network Mode & IP', 'Modo de red e IP', 'Netzwerkmodus & IP', '网络模式与 IP', 'Mode réseau et IP'),
 ('Ağ Modu & IP Tespiti', 'Network Mode & IP Detection', 'Detección de modo de red e IP', 'Netzwerkmodus- & IP-Erkennung', '网络模式与 IP 检测', 'Détection du mode réseau et de l\'IP'),
 ('Ağlar — Tespit Edilen Mod', 'Networks — Detected Mode', 'Redes — modo detectado', 'Netzwerke — erkannter Modus', '网络 — 检测到的模式', 'Réseaux — mode détecté'),
 ('Gerçek IP (guest-agent)', 'Real IP (guest-agent)', 'IP real (guest-agent)', 'Echte IP (Guest-Agent)', '真实 IP (guest-agent)', 'IP réelle (agent invité)'),
 ('IP Kaynağı', 'IP Source', 'Origen de IP', 'IP-Quelle', 'IP 来源', 'Source IP'),
 ('NAT/Routed/İzole', 'NAT/Routed/Isolated', 'NAT/Enrutado/Aislado', 'NAT/Geroutet/Isoliert', 'NAT/路由/隔离', 'NAT/Routé/Isolé'),
 ('Neden bazı VM\'ler yanlış IP gösteriyor?', 'Why do some VMs show the wrong IP?', '¿Por qué algunas VM muestran la IP incorrecta?', 'Warum zeigen manche VMs die falsche IP?', '为什么有些虚拟机显示错误的 IP？', 'Pourquoi certaines VM affichent-elles une mauvaise IP ?'),
 ('Panel IP (libvirt)', 'Panel IP (libvirt)', 'IP del panel (libvirt)', 'Panel-IP (libvirt)', '面板 IP (libvirt)', 'IP du panneau (libvirt)'),
 ('Panel IP Güvenilir?', 'Panel IP Reliable?', '¿IP del panel fiable?', 'Panel-IP zuverlässig?', '面板 IP 可靠？', 'IP du panneau fiable ?'),
 ('VM IP Denetimi (gerçek vs panel)', 'VM IP Audit (real vs panel)', 'Auditoría de IP de VM (real vs panel)', 'VM-IP-Audit (echt vs. Panel)', '虚拟机 IP 审计（真实 vs 面板）', 'Audit IP de VM (réel vs panneau)'),
 ('ağlarda IP\'yi', 'networks the IP', 'redes la IP', 'Netzwerken die IP', '网络中，IP', 'réseaux, l\'IP'),
 ('ağlarda IP\'yi libvirt\'in kendi DHCP\'si (dnsmasq) verir → panel lease\'den', "networks libvirt's own DHCP (dnsmasq) assigns the IP → the panel reads it from the lease", "redes el propio DHCP de libvirt (dnsmasq) asigna la IP → el panel la lee del lease", "Netzwerken vergibt libvirts eigenes DHCP (dnsmasq) die IP → das Panel liest sie aus dem Lease", '网络中，由 libvirt 自带的 DHCP (dnsmasq) 分配 IP → 面板从租约读取', "réseaux, le DHCP propre à libvirt (dnsmasq) attribue l'IP → le panneau la lit depuis le bail"),
 ('doğru', 'correctly', 'correctamente', 'korrekt', '正确', 'correctement'),
 ('verir, libvirt lease tutmaz → DHCP\'ye bakan görünüm yanlış/host IP gösterebilir. Gerçek IP', 'assigns it, libvirt keeps no lease → a DHCP-based view may show a wrong/host IP. The real IP', 'la asigna, libvirt no mantiene lease → una vista basada en DHCP puede mostrar una IP errónea/del host. La IP real', 'vergibt sie, libvirt führt kein Lease → eine DHCP-basierte Ansicht kann eine falsche/Host-IP zeigen. Die echte IP', '分配它，libvirt 不保留租约 → 基于 DHCP 的视图可能显示错误/主机 IP。真实 IP', 'l\'attribue, libvirt ne conserve pas de bail → une vue basée sur DHCP peut afficher une IP erronée/de l\'hôte. L\'IP réelle'),
 ("'tan alınır. Aşağıda her ağın modu ve her VM'in gerçek IP'si görünür.", 'is taken from it. Below, each network\'s mode and each VM\'s real IP are shown.', 'se toma de ahí. Abajo se muestran el modo de cada red y la IP real de cada VM.', 'wird daraus bezogen. Unten werden der Modus jedes Netzwerks und die echte IP jeder VM angezeigt.', '由此获取。下方显示每个网络的模式和每台虚拟机的真实 IP。', 'en est issue. Ci-dessous, le mode de chaque réseau et l\'IP réelle de chaque VM sont affichés.'),
 # sekme grupları
 ('Sistem', 'System', 'Sistema', 'System', '系统', 'Système'),
 ('Entegrasyon', 'Integration', 'Integración', 'Integration', '集成', 'Intégration'),
 ('Otomasyon', 'Automation', 'Automatización', 'Automatisierung', '自动化', 'Automatisation'),
 ('Cloud-Native', 'Cloud-Native', 'Cloud-Native', 'Cloud-Native', '云原生', 'Cloud-Native'),
 ('Araçlar', 'Tools', 'Herramientas', 'Werkzeuge', '工具', 'Outils'),
 ('Güvenlik & Uyum', 'Security & Compliance', 'Seguridad y cumplimiento', 'Sicherheit & Compliance', '安全与合规', 'Sécurité et conformité'),
 # v2.8.1 — gerçek IP + thumbnail toggle
 ('VM canlı küçük resimleri (kapatmak CPU/bant tasarrufu sağlar)', 'Live VM thumbnails (turn off to save CPU/bandwidth)', 'Miniaturas en vivo de VM (desactiva para ahorrar CPU/ancho de banda)', 'Live-VM-Vorschaubilder (zum Sparen von CPU/Bandbreite deaktivieren)', '虚拟机实时缩略图（关闭可节省 CPU/带宽）', 'Miniatures de VM en direct (désactiver pour économiser CPU/bande passante)'),
 ('Küçük resimler açık', 'Thumbnails on', 'Miniaturas activadas', 'Vorschaubilder an', '缩略图已开启', 'Miniatures activées'),
 ('Küçük resimler kapalı', 'Thumbnails off', 'Miniaturas desactivadas', 'Vorschaubilder aus', '缩略图已关闭', 'Miniatures désactivées'),
 ("Gerçek IP guest-agent'tan", 'Real IP from guest agent', 'IP real desde el guest agent', 'Echte IP vom Guest-Agent', '来自 guest-agent 的真实 IP', 'IP réelle depuis l\'agent invité'),
 ('Port grup adı gerekli', 'Port group name required', 'Se requiere nombre de grupo de puertos', 'Portgruppenname erforderlich', '需要端口组名称', 'Nom de groupe de ports requis'),
 ('Port Grup', 'Port Groups', 'Grupos de puertos', 'Portgruppen', '端口组', 'Groupes de ports'),
 # v2.8.1 — Flight Recorder / Runbook gen / What-If / Heatmap
 ('AI Otopsi', 'AI Post-Mortem', 'Autopsia IA', 'KI-Post-Mortem', 'AI 事后分析', 'Post-mortem IA'),
 ('AI Runbook Üretici', 'AI Runbook Generator', 'Generador de runbooks IA', 'KI-Runbook-Generator', 'AI Runbook 生成器', 'Générateur de runbook IA'),
 ('CPU 5 dakika %90 üstündeyse...', 'If CPU stays above 90% for 5 minutes...', 'Si la CPU supera el 90% durante 5 minutos...', 'Wenn die CPU 5 Minuten über 90% bleibt...', '如果 CPU 持续 5 分钟超过 90%……', 'Si le CPU dépasse 90% pendant 5 minutes...'),
 ('Canlı Isı Haritası', 'Live Heat Map', 'Mapa de calor en vivo', 'Live-Heatmap', '实时热力图', 'Carte thermique en direct'),
 ('Doğal dil → otomasyon kuralı', 'Natural language → automation rule', 'Lenguaje natural → regla de automatización', 'Natürliche Sprache → Automatisierungsregel', '自然语言 → 自动化规则', 'Langage naturel → règle d\'automatisation'),
 ('Kara kutu kaydı için "Kaydı Getir" tıkla.', 'Click "Fetch Record" for the black-box recording.', 'Haz clic en "Obtener registro" para la grabación de la caja negra.', 'Für die Black-Box-Aufzeichnung auf „Aufzeichnung abrufen" klicken.', '点击"获取记录"查看黑匣子记录。', 'Cliquez sur « Récupérer l\'enregistrement » pour l\'enregistrement de la boîte noire.'),
 ('Kaydı Getir', 'Fetch Record', 'Obtener registro', 'Aufzeichnung abrufen', '获取记录', 'Récupérer l\'enregistrement'),
 ('Runbook Üret', 'Generate Runbook', 'Generar runbook', 'Runbook generieren', '生成 Runbook', 'Générer un runbook'),
 ('Simüle Et', 'Simulate', 'Simular', 'Simulieren', '模拟', 'Simuler'),
 ('What-If Kapasite Simülatörü', 'What-If Capacity Simulator', 'Simulador de capacidad What-If', 'What-If-Kapazitätssimulator', 'What-If 容量模拟器', 'Simulateur de capacité What-If'),
 ('devre dışı', 'disabled', 'desactivado', 'deaktiviert', '已禁用', 'désactivé'),
 ('üretilir; onaylayıp etkinleştirirsin.', 'is generated; you review and enable it.', 'se genera; lo revisas y lo activas.', 'wird erzeugt; du prüfst und aktivierst es.', '生成后由你审核并启用。', 'est généré ; vous le vérifiez et l\'activez.'),
 ('"X VM daha eklesem ne olur?" — uygulamadan önce CPU/RAM/güç/maliyet/karbon etkisini canlı kullanım + host kapasitesi üstünden tahmin eder. Rakiplerde yok.', '"What if I add X more VMs?" — estimates the CPU/RAM/power/cost/carbon impact before you act, from live usage + host capacity. Competitors don\'t have it.', '"¿Y si añado X VMs más?" — estima el impacto en CPU/RAM/energía/costo/carbono antes de actuar, según el uso en vivo + la capacidad del host. Los competidores no lo tienen.', '„Was, wenn ich X weitere VMs hinzufüge?" — schätzt die CPU-/RAM-/Strom-/Kosten-/CO₂-Auswirkung vor dem Handeln aus Live-Nutzung + Host-Kapazität. Konkurrenten haben das nicht.', '"如果再加 X 台虚拟机会怎样？"——在操作前根据实时用量 + 主机容量估算 CPU/内存/功耗/成本/碳影响。竞品没有此功能。', '« Et si j\'ajoute X VM de plus ? » — estime l\'impact CPU/RAM/énergie/coût/carbone avant d\'agir, à partir de l\'usage en direct + la capacité de l\'hôte. Les concurrents ne l\'ont pas.'),
 ('Doğal dil ile otomasyon kuralı yaz. Örn: "CPU 5 dk %90 üstündeyse uyarı gönder ve VM\'i yeniden başlat". Taslak', 'Write an automation rule in natural language. E.g. "if CPU stays above 90% for 5 min, send an alert and reboot the VM". The draft', 'Escribe una regla de automatización en lenguaje natural. Ej.: "si la CPU supera el 90% durante 5 min, envía una alerta y reinicia la VM". El borrador', 'Schreibe eine Automatisierungsregel in natürlicher Sprache. Z. B. „wenn die CPU 5 Min über 90% bleibt, sende eine Warnung und starte die VM neu". Der Entwurf', '用自然语言编写自动化规则。例如"如果 CPU 持续 5 分钟超过 90%，发送告警并重启虚拟机"。草稿', 'Écrivez une règle d\'automatisation en langage naturel. Ex. : « si le CPU dépasse 90% pendant 5 min, envoyer une alerte et redémarrer la VM ». Le brouillon'),
 ("Tüm VM'lerin yükünü tek bakışta renk haritasıyla gör (yeşil=düşük, kırmızı=yüksek CPU). Yoğun VM'leri anında ayırt et.", 'See every VM\'s load at a glance via a colour map (green=low, red=high CPU). Spot busy VMs instantly.', 'Ve la carga de cada VM de un vistazo con un mapa de color (verde=baja, rojo=CPU alta). Detecta VMs ocupadas al instante.', 'Sieh die Last jeder VM auf einen Blick als Farbkarte (grün=niedrig, rot=hohe CPU). Erkenne ausgelastete VMs sofort.', '通过颜色图一眼看清每台虚拟机的负载（绿=低，红=高 CPU）。立即发现繁忙虚拟机。', 'Voyez la charge de chaque VM d\'un coup d\'œil via une carte de couleurs (vert=faible, rouge=CPU élevé). Repérez instantanément les VM occupées.'),
 ('Açıklama gir', 'Enter a description', 'Introduce una descripción', 'Beschreibung eingeben', '输入描述', 'Saisissez une description'),
 ('Runbook kaydedildi (devre dışı — Runbook sayfasından etkinleştir)', 'Runbook saved (disabled — enable it from the Runbook page)', 'Runbook guardado (desactivado — actívalo desde la página de Runbook)', 'Runbook gespeichert (deaktiviert — auf der Runbook-Seite aktivieren)', 'Runbook 已保存（已禁用——在 Runbook 页面启用）', 'Runbook enregistré (désactivé — activez-le depuis la page Runbook)'),
]

LANG_IDX = {"en": 1, "es": 2, "de": 3, "zh": 4, "fr": 5}
NEW = {r[0]: {l: r[LANG_IDX[l]] for l in LANGS} for r in ROWS}


def _required_keys():
    keys = []
    for fn in ("missing_html_tr.txt", "missing_js_tr.txt"):
        p = os.path.join(OUT, fn)
        if os.path.exists(p):
            for ln in open(p, encoding="utf-8").read().split("\n"):
                if ln.strip():
                    keys.append(ln)
    return keys


def main():
    req = _required_keys()
    missing = [k for k in req if k not in NEW]
    if missing:
        print("!! ÇEVİRİSİ EKSİK (NEW'e ekle):")
        for k in missing:
            print("   ", repr(k))
        sys.exit(1)
    for lang in LANGS:
        path = os.path.join(OUT, f"{lang}.json")
        d = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
        for tr, langs in NEW.items():
            d[tr] = langs[lang]
        json.dump(d, open(os.path.join(OUT, f"{lang}_full.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=0)
        print(f"{lang}: +{len(NEW)} -> {len(d)} entries ({lang}_full.json)")
    print("OK -> run: python scripts/i18n_inject.py")


if __name__ == "__main__":
    main()
