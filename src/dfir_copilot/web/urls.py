from django.urls import path

from dfir_copilot.web import views

# Las vistas de un caso cuelgan de dos prefijos: el de un proyecto y el de los casos sueltos (los de `data/cases`, anteriores a los proyectos).
CASE_ROUTES = [
    ("", views.case_page, "case"),
    ("tab/<str:tab>/", views.tab_view, "case_tab"),
    ("preguntar/", views.ask, "case_ask"),
    ("decidir/", views.decide, "case_decide"),
    ("job/<str:job_id>/", views.job_view, "case_job"),
    ("retirar/<str:hid>/", views.retire, "case_retire"),
    ("notas/", views.note, "case_note"),
    ("informe/exportar/", views.export, "case_export"),
    ("informe/descargar/<str:filename>/", views.download, "case_download"),
    ("zona/", views.timezone_confirm, "case_timezone"),
    ("reiniciar/", views.reset_conversation, "case_reset"),
    ("perfil/", views.compute_profile, "case_profile"),
]

urlpatterns = [
    path("", views.home, name="home"),
    path("healthz", views.healthz, name="healthz"),
    path("analisis/nuevo/", views.analysis_new, name="analysis_new"),
    path("proyectos/nuevo/", views.project_create, name="project_create"),
    path("proyectos/<str:pid>/archivos/", views.evidence_page, name="evidence"),
    path("proyectos/<str:pid>/archivos/subir/", views.evidence_upload, name="evidence_upload"),
    path("proyectos/<str:pid>/archivos/servidor/", views.evidence_browse, name="evidence_browse"),
    path("proyectos/<str:pid>/archivos/servidor/agregar/", views.evidence_add, name="evidence_add"),
    path("proyectos/<str:pid>/archivos/analizar/", views.evidence_analyze, name="evidence_analyze"),
    path("proyectos/<str:pid>/", views.project_page, name="project"),
    path("proyectos/<str:pid>/estado/", views.project_status, name="project_status"),
    path("proyectos/<str:pid>/analizar/<str:cid>/", views.project_run, name="project_run"),
]
for route, view, name in CASE_ROUTES:
    urlpatterns.append(path(f"proyectos/<str:pid>/casos/<str:cid>/{route}", view, name=f"project_{name}"))
    urlpatterns.append(path(f"casos/<str:cid>/{route}", view, {"pid": None}, name=name))
