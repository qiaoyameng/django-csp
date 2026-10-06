from django.urls import path

from csp.contrib import reports
from csp.tests.report_callbacks import collect_callback

urlpatterns = [
    path("csp-report/legacy", reports.csp_report_view),
    path("csp-report/reporting", reports.csp_report_view),
    path(
        "csp-report/collect",
        reports.report_view(collect_callback),
    ),
]
