# Copyright (c) Siemens AG, 2015
#
# This file is part of MANTIS.  MANTIS is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2
# of the License, or(at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# -*- coding: utf-8 -*-

from django.conf.urls import patterns, url
from .views import *

urlpatterns = patterns(
    'mantis_actionables.views',

    url(r'^indicators_by_source/$',
        SourceInfoView.as_view(),
        name='actionables_all_imports'),

    url(r'^unified_search/(?P<search_term>.*)$',
        UnifiedSearch.as_view(),
        name='actionables_unified_search'),
    url(r'^indicator_status_infos/$',
        StatusInfoView.as_view(), name='actionables_all_status_infos'),
    #url(r'^refresh/$', 'refresh', name='refresh'),
    url(r'^tbl_data/indicators_by_source$',
        SingeltonObservablesWithSourceOneTableDataProvider.as_view(),
        name=SingeltonObservablesWithSourceOneTableDataProvider.qualified_view_name()),
    url(r'^dashboard/$',
        Dashboard.as_view(), name='actionables_dashboard'),
    url(r'^tbl_data/dashboard$',
        DashboardDataProvider.as_view(), name=DashboardDataProvider.qualified_view_name()),

    url(r'^tbl_data/unified_search$',
        UnifiedSearchSourceDataProvider.as_view(),
        name=UnifiedSearchSourceDataProvider.qualified_view_name()),
    url(r'^tbl_data/indicator_status_infos$',
        SingletonObservablesWithStatusOneTableDataProvider.as_view(),
        name=SingletonObservablesWithStatusOneTableDataProvider.qualified_view_name()),
    url(r'^context/(?P<context_name>[a-zA-Z0-9_\-]+)/?$', ActionablesContextView.as_view(), name='actionables_context_view'),
    url(r'^context/(?P<context_name>[a-zA-Z0-9_\-]+)/edit$', ActionablesContextEditView.as_view(), name='actionables_context_edit_view'),
    url(r'^context/?$', ActionablesContextList.as_view(), name='actionables_context_list'),
    url(r'^import_info/?$', ImportInfoList.as_view(), name='actionables_import_info_list'),
    url(r'^import_info/(?P<pk>\d*)$',
        ImportInfoDetailsView.as_view(),
        name= "actionables_import_info_details"),
    url(r'^singleton_observable/(?P<pk>\d*)$',
        SingletonObservableDetailView.as_view(),
        name= "actionables_singleton_observables_details"),
    url(r'^context/(?P<context_name>[a-zA-Z0-9_\-]+)/history$', ActionablesTagHistoryView.as_view(), name='actionables_context_history_view'),
    #url(r'^tbl_data_export$', 'table_data_source_export', name='table_data_source_export'),

    #Actions
    url(r'^action/investigate$', BulkInvestigationFilterView.as_view(), name= "actionables_action_investigate"),

    #Bulk Search
    url(r'^bulk_search/$', BulkSearchView.as_view(), name="actionables_bulk_search"),
    url(r'^bulk_search/result/$', BulkSearchResultView.as_view(), name="actionables_bulk_search_result"),
    url(r'^tbl_data/bulk_search_result_simple$', BulkSearchResultTableDataProvider.as_view(), name="actionables_dataprovider_singletons_bulk_search_default"),
    url(r'^tbl_data/bulk_search_result_by_source$', BulkSearchResultTableDataProviderBySource.as_view(), name="actionables_dataprovider_singletons_bulk_search_by_source"),

)
