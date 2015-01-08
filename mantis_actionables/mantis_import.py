
# -*- coding: utf-8 -*-

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
import ipaddr, datetime, re

from django.contrib.contenttypes.models import ContentType
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

from dingos.models import InfoObject,vIO2FValue
from dingos.view_classes import POSTPROCESSOR_REGISTRY
from dingos.graph_traversal import follow_references

from . import ACTIVE_MANTIS_EXPORTERS, STIX_REPORT_FAMILY_AND_TYPES
from .models import SingletonObservable, SingletonObservableType, Source

#build a name to pk mapping for SingletonObservableTypes on server startup
singleton_observable_types = {}
singleton_observable_types_qs = SingletonObservableType.objects.all()
for type in singleton_observable_types_qs:
    singleton_observable_types[type.name] = type.pk

#color tlp mapping
tlp_color_map = {}
for (id,color) in Source.TLP_KIND:
    tlp_color_map[color.lower()] = id

#content_type_id
CONTENT_TYPE_SINGLETON_OBSERVABLE = ContentType.objects.get_for_model(SingletonObservable)

def is_valid_fqdn(fqdn):
    if len(fqdn) > 255:
        return False
    if fqdn[-1] == ".":
        fqdn = fqdn[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in fqdn.split("."))

def is_valid_url(url):
    val = URLValidator()
    try:
        val(url)
    except ValidationError:
        return False
    return True

def extract_singleton_observable(exporter_result):
    """
    Given the dictionary resulting from the run of a MANTIS exporter,
    derive the primitive observable type and value.

    Here is an example of what the exporter returns, e.g. for IPs::

          {
          "category": "ipv4-addr",
          "object.import_timestamp": "2014-09-04 14:26:32.327645+00:00",
          "exporter": "IPs",
          "ip": "127.0.0.1",
          "object.name": "127.0.0.1 (1 facts)",
          "object.url": "/mantis/View/InfoObject/446977/",
          "object.object_family": "cybox.mitre.org",
          "object.identifier.namespace": "cert.test.siemens.com",
          "object.pk": "446977",
          "object.timestamp": "2014-09-04 14:26:32.254963+00:00",
          "apply_condition": "",
          "object.object_type.name": "AddressObject",
          "fact.pk": "225652",
          "object.identifier.uid": "Address-260a70ed-8f68-4de4-e760-61176b3ad20c-06368",
          "condition": ""
          }

    Currently, the function should to the following:

    - for results from ip report:
      - use a suitable python library to parse the result and
        return type 'IPv4' or 'IPv6'; return 'None' for anything
        else (slash notation etc.).
      - return the yielded ip as value

    - for results from hash export:
      - If hash type is provided, return the provided type
      - Otherwise, use heuristics to recognize MD5, SHA1, SHA256
      - Provide yielded hash as value

    - for results from fqdn:
      - Use python code e.g. from http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        to return either type "FQDN" or "URL"
      - Return the provided fqdn as value
    """
    exporter = exporter_result.get('exporter')
    if exporter:
        if exporter == "IPs":
            try:
                ip = ipaddr.IPAddress(exporter_result['ip'])
            except ValueError:
                #invalid ip address
                return (None,exporter_result['ip'])
            if ip.version == 4:
                return ('IPv4',exporter_result['ip'])
            else:
                return ('IPv6',exporter_result['ip'])

        elif exporter == "hashes":
            #TODO add ALL supported valid_hashtypes
            #valid_hashtypes = ['MD5','SHA1','SHA256']
            hash_type = exporter_result.get('hash_type')
            hash_value = exporter_result.get('hash_value')
            if hash_value:
                if hash_type: #and hash_type in valid_hashtypes:
                    return (hash_type,hash_value)
                else:
                    """
                    By the definition in FIPS 180-4, published March 2012, there are
                    160 bits in the output of SHA-1
                    224 bits in the output of SHA-224
                    256 bits in the output of SHA-256
                    384 bits in the output of SHA-384
                    512 bits in the output of SHA-512
                    224 bits in the output of SHA-512/224
                    256 bits in the output of SHA-512/256
                    """
                    length_hashtype_map = {
                        32 : "MD5",
                        40 : "SHA1",
                        64 : "SHA256"
                    }

                    try:
                        hash_type = length_hashtype_map[len(hash_value)]
                        return (hash_type,hash_value)
                    except KeyError:
                        #no suiting hash_type found
                        return (None,None)
            else:
                return (None,None)

        elif exporter == "fqdn":
            to_validate = exporter_result['fqdn']
            if(is_valid_fqdn(to_validate)):
                return ('FQDN',to_validate)
            elif(is_valid_url(to_validate)):
                return ('URL',to_validate)
            return (None,None)

    #exception, no exporter found
    print "NO EXPORTER FOUND named %s" % (exporter)
    return (None,None)


def process_STIX_Reports(imported_since, imported_until=None):
    """
    Process all STIX reports that have been imported into MANTIS in a certain time slice.

    process_STIX_Reports carries out the following steps:

    - it performs a query that yields all STIX reports that have been imported
      since the date-time provided by the parameter ``imported_since`` and no later
      than the date-time provided by the parameter ``imported_until`` (if no
      such date has been provided, then all reports up to the present time are taken.

      What consitutes a STIX report is configurable via the setting

      STIX_REPORT_FAMILY_AND_TYPES specified in ``__init__.py``. The default
      setting is thus::

         STIX_REPORT_FAMILY_AND_TYPES = [{'iobject_type': 'STIX_Package',
                                          'iobject_type_family': 'stix.mitre.org'}]

      (Once STIX 1.2 is released, we may have to add STIX_Report here and probably
      add some intelligence to disregard packages if they contain a report object...)

    - For each object yielded by the query for STIX reports, the fucntion carries
      out the imports specified in ACTIVE_MANTIS_EXPORTERS as specified in ``__init__.py``.
      The default setting is thus:

         ACTIVE_MANTIS_EXPORTERS = ['hashes','ips','fqdns']

      The  values in the list refer to the name specified in
      ``mantis_stix_importer.STIX_POSTPROCESSOR_REGISTRY``.

      Implementation hints for Philipp:

      - See the code in``dingos.views.InfoObjectExportsView`` for how to run an exporter.
      - Call the exporter with argument "override_columns = 'ALMOST_ALL'" to
        get complete information.

    - The function concatenates the results of all exporter runs. Here is an example
      single result of an IP export:

         {
          "category": "ipv4-addr",
          "object.import_timestamp": "2014-09-04 14:26:32.327645+00:00",
          "exporter": "IPs",
          "ip": "127.0.0.1",
          "object.name": "127.0.0.1 (1 facts)",
          "object.url": "/mantis/View/InfoObject/446977/",
          "object.object_family": "cybox.mitre.org",
          "object.identifier.namespace": "cert.test.siemens.com",
          "object.pk": "446977",
          "object.timestamp": "2014-09-04 14:26:32.254963+00:00",
          "apply_condition": "",
          "object.object_type.name": "AddressObject",
          "fact.pk": "225652",
          "value.pk": "123456",
          "object.identifier.uid": "Address-260a70ed-8f68-4de4-e760-61176b3ad20c-06368",
          "condition": ""
         }

    - The function extracts the set of all 'object.pk's. It then queries MANTIS for all
      facts in marking objects that are associated as markings with one of these objects
      and contain the fact_term with term 'Marking_Structure' and attribute '@color'
      and builds a dictionary mapping object-pks to TLP color (ignoring differences
      in lower/upper case)

    - For each export result, the function calls ``extract_singleton_observable`` to
      extract singleton observable type and value. It then does the following:

      - get or create the SingletonObservable object (please be smart about
        handling the SingletonObservableType: instead of querying for the pk
        again and again, use a global dictionary to store a mapping from
        type-name to pk and only look up types in the database
        that have not been encountered before

      - create a Source object and fills in
        - the links to the MANTIS-observables
        - TLP information
        - leave ORIGIN set to uncertain for now.

    """
    print "color map"
    print tlp_color_map


    if not imported_until:
        imported_until = datetime.datetime.now()
    filter = STIX_REPORT_FAMILY_AND_TYPES[0]
    matching_stix = InfoObject.objects.filter(#create_timestamp__gte=imported_since,
                                              #create_timestamp__lte=imported_until,
                                              iobject_type__name=filter['iobject_type'],
                                              iobject_family__name=filter['iobject_type_family'],
                                              id=48)
    #TODO multiple familys and types concat by OR

    #TODO needed??
    skip_terms = [{'term':'Related','operator':'icontains'}]
    for stix in matching_stix:
        graph= follow_references([stix.id],
                                 skip_terms = skip_terms,
                                 direction='down'
                                 )

        for exporter in ACTIVE_MANTIS_EXPORTERS:
            postprocessor_class = POSTPROCESSOR_REGISTRY[exporter]
            postprocessor = postprocessor_class(graph=graph,
                                                query_mode='vIO2FValue',
                                                )
            (content_type,results) = postprocessor.export(override_columns = 'ALMOST_ALL', format='dict')
            if results:
                iobject_pks = [result['object.pk'] for result in results]
                select_columns = ['id','marking_thru__marking__fact_thru__fact__fact_values__value']
                color_qs = InfoObject.objects.filter(id__in=iobject_pks)\
                    .filter(marking_thru__marking__fact_thru__fact__fact_term__term='Marking_Structure', marking_thru__marking__fact_thru__fact__fact_term__attribute='color')\
                    .values_list(*select_columns)
                iobj_to_color = {}
                for map in color_qs:
                    iobj_to_color[map[0]] = map[1].lower()

                for result in results:
                    iobj_pk = int(result['object.pk'])
                    fact_pk = int(result['fact.pk'])
                    fact_value_pk = int(result['value.pk'])
                    (type,value) = extract_singleton_observable(result)
                    if not (type and value):
                        continue
                    try:
                        type_pk = singleton_observable_types[type]
                    except KeyError:
                        obj, created = SingletonObservableType.objects.get_or_create(name=type)
                        singleton_observable_types[type] = obj.pk
                        type_pk = obj.pk

                    obj, created = SingletonObservable.objects.get_or_create(type_id=type_pk,value=value)
                    if created:
                        print "singleton created (%s,%s)" % (type,value)
                    else:
                        print "singleton not created, already in database"

                    obj, created = Source.objects.get_or_create(timestamp=datetime.datetime.now(),
                                                                iobject_id=iobj_pk,
                                                                iobject_fact_id=fact_pk,
                                                                iobject_factvalue_id=fact_value_pk,
                                                                top_level_iobject=stix,
                                                                origin=Source.ORIGIN_UNCERTAIN,
                                                                tlp=tlp_color_map.get(iobj_to_color.get(iobj_pk,None),Source.TLP_UNKOWN),
                                                                object_id=obj.id,
                                                                content_type=CONTENT_TYPE_SINGLETON_OBSERVABLE
                                                                )

                    if created:
                        print "source object created (%s,%s)" % (iobj_pk,iobj_to_color.get(iobj_pk,'TLP_UNKOWN'))
                    else:
                        print "source not created, already in database"