# OXware örnek eklenti — Hello World
# Bu dosyayı panelden Ayarlar > Eklentiler > Geliştir sekmesinde
# içe aktarabilir veya doğrudan yükleyebilirsiniz.

PLUGIN_META = {
    "id": "hello-world",
    "name": "Hello World Plugin",
    "version": "1.0",
    "author": "OXware",
    "description": "Minimal örnek: /api/plugin/hello route ekler.",
    "api_version": "1.0",
}


def register_routes(app):
    """OXware başlatılırken çağrılır. Flask app'e route ekleyebilirsin."""
    @app.route("/api/plugin/hello")
    def _plugin_hello():
        from flask import jsonify
        return jsonify({"message": "Merhaba OXware!", "plugin": PLUGIN_META["id"]})


def on_vm_event(event):
    """VM olayları (vm.created, vm.deleted, vm.started, ...) burada yakalanır."""
    # event = {"type": "vm.created", "vm_id": "...", "name": "..."}
    pass
