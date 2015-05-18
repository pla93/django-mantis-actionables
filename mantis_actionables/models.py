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

import logging
import json

from django.db import models
from django.contrib.auth.models import User, Group
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.core.cache import caches
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from datetime import datetime

from django.utils import timezone

from dingos.models import InfoObject, Fact, FactValue, IdentifierNameSpace, Identifier

from taggit.models import TagBase, GenericTaggedItemBase
from taggit.managers import TaggableManager, _TaggableManager
from taggit.utils import require_instance_manager
from django.utils.translation import ugettext_lazy as _

logger = logging.getLogger(__name__)

import read_settings

class CachingManager(models.Manager):
    """
    For models that have a moderate amount of entries and are always queried
    with ``get_or_create`` using the same argument(s) (usually, list-of-value definitions such as
    types, namespaces, etc,) use this CachingManager to enable easy querying
    while avoiding to hit the database every time.

    To use for a model:

    - include model name and query for which a cache is to be maintained in
      the mapping 'cachable_queries' as follows::
          cachable_queries = {
                              # Make sure that the query arguments below are given in alphabetical order!!!
                              ...
                              "ActionableTag" : ["context_id","tag_id"]
                              ...
                            }

      So queries of form ``get_or_create(context_id=bla,tag_id=bla)
      can now be answered from the cache
    - include the cached manager in the model definition as follows::

         objects = models.Manager()
         cached_objects = CachingManager()

      and use ``ActionableTag.cached_objects.get_or_create(...)`` for the query.

    """

    TIME_TO_LIVE = None

    cache = caches['caching_manager']

    cachable_queries = {
        # Make sure that the query arguments below are given in alphabetical order!!!
        "SingletonObservableType" : ['name'],
        "SingletonObservableSubtype" : ['name'],
        "Context" : ["name"],
        "TagInfo" : ['name'],
        "EntityType" : ["name"],
        "ActionableTag" : ["context_id","info_id"]
    }

    def get_or_create(self, defaults=None, **kwargs):
        sorted_keys = sorted(kwargs.keys())
        sorted_arguments = tuple(sorted(kwargs.values()))
        if sorted_keys == sorted(CachingManager.cachable_queries[self.model.__name__]):
            if not CachingManager.cache.get(self.model.__name__):
                all_objects = list(super(CachingManager, self).all())
                value_dic = {}
                for object in all_objects:
                    # TODO: When the cache is filled for the first time, the line below
                    # leads to a query for each single object. I thought that the
                    # wrapping 'list(...)' above when getting all objects would take care of
                    # this, but it does not... Can this be changed? otherwise, initializing
                    # the cache is really expensive...
                    sorted_values = tuple(sorted([getattr(object, attr) for attr in sorted_keys]))
                    value_dic[sorted_values] = object
                CachingManager.cache.set(self.model.__name__, value_dic, CachingManager.TIME_TO_LIVE)


            inCache = CachingManager.cache.get(self.model.__name__).get(sorted_arguments)

            if inCache:
                return inCache, False

            else:
                (object, created)  = super(CachingManager, self).get_or_create(defaults=defaults, **kwargs)
                CachingManager.cache.get(self.model.__name__)[sorted_arguments] = object
                return object, created
        else:
            (object, created)  = super(CachingManager, self).get_or_create(defaults=defaults, **kwargs)


class ActionableTaggableManager(_TaggableManager):

    @require_instance_manager
    def add(self, *tags):
        tag_objs = set()
        tag_pks = set()
        for t in tags:
            if isinstance(t, self.through.tag_model()):
                tag_objs.add(t)
            elif isinstance(t, int):
                tag_pks.add(t)
            else:
                raise ValueError("Cannot add {0} ({1}). Expected {2} or int.".format(
                    t, type(t), type(self.through.tag_model())))

        for tag in tag_objs:
            self.through.objects.get_or_create(tag=tag, **self._lookup_kwargs())
        for tag_pk in tag_pks:
            self.through.objects.get_or_create(tag_id=tag_pk, **self._lookup_kwargs())

    @require_instance_manager
    def remove(self, *tags):
        tag_pks = [x.id if isinstance(x,self.through.tag_model()) else x for x in tags]
        self.through.objects.filter(**self._lookup_kwargs()).filter(
            tag_id__in=tag_pks).delete()


class TagInfo(models.Model):
    name = models.CharField(max_length=40,unique=True)
    objects = models.Manager()
    cached_objects = CachingManager()

    def __unicode__(self):
        return "%s" % (self.name)


class ActionableTag(TagBase):
    context = models.ForeignKey('Context',
                                null=True)

    info = models.ForeignKey(TagInfo)

    objects = models.Manager()
    cached_objects = CachingManager()

    class Meta:
        verbose_name = _("ActionableTag")
        verbose_name_plural = _("ActionableTags")
        unique_together=('context','info')

    def unique_id(self):
        return "%s:%s" % (self.context.name,self.info.name)

    def save(self, *args, **kwargs):
        if not self.name or self.name == 'fill-in':
            self.name = self.unique_id()
            self.slug = self.slugify(self.name)
        return super(ActionableTag, self).save(*args, **kwargs)

    @classmethod
    def bulk_action(cls,
                    action,
                    context_name_pairs,
                    # TODO: once we want to generalize, allowing tagging of other
                    # things, we need to also the model for each pk
                    thing_to_tag_pks,
                    thing_to_tag_model=None,
                    user=None,
                    comment='',
                    supress_transfer_to_dingos=False):

        """
        Input:
        - action: either 'add' or 'remove'
        - context_name_pairs: list of pairs '('context','tag_name')' denoting
          the actionable tags to added or removed
        - things_to_tag_pks: pks of SingletonObjects to be tagged
        - user: user object of user doing the tagging
        - comment: comment string

        The function carries out the action (addition or removing) of the
        provided actionable tags and also fills in the actionable-tag history.


        """
        # TODO: Import must be here, otherwise we get an exception "models not ready
        # at startup.
        from .mantis_import import update_and_transfer_tag_action_to_dingos
        # The content type must be defined here: defining it outside the function
        # leads to a circular import
        if not thing_to_tag_model:
            CONTENT_TYPE_OF_THINGS_TO_TAG = ContentType.objects.get_for_model(SingletonObservable)
        else:
            CONTENT_TYPE_OF_THINGS_TO_TAG = ContentType.objects.get_for_model(thing_to_tag_model)

        # Create the list of actionable tags for this bulk action
        actionable_tag_list = []

        context_name_set = set([])
        for (context_name,tag_name) in context_name_pairs:

            context,created = Context.cached_objects.get_or_create(name=context_name,
                                                                   defaults={'type':Context.TYPE_RMAP.get(context_name.split('-')[0].lower(),
                                                                                                          Context.TYPE_INVESTIGATION)})

            context_name_set.add(context_name)

            tag_info, created = TagInfo.cached_objects.get_or_create(name=tag_name)

            actionable_tag, created = ActionableTag.cached_objects.get_or_create(info_id=tag_info.id,
                                                                                 context_id=context.id)

            actionable_tag_list.append(actionable_tag)

        logger.debug("Got actionable tags %s from DB" % actionable_tag_list)

        if action == 'add':
            action_flag = ActionableTaggingHistory.ADD
        elif action == 'remove':
            action_flag = ActionableTaggingHistory.REMOVE

        for pk in thing_to_tag_pks:
            for actionable_tag in actionable_tag_list:
                affected_tags = set([])
                if action_flag == ActionableTaggingHistory.ADD:

                    tagged_actionable_item, created = TaggedActionableItem.objects.get_or_create(tag_id=actionable_tag.id,
                                                               object_id=pk,
                                                               content_type=CONTENT_TYPE_OF_THINGS_TO_TAG)

                    if created:
                        affected_tags.add(actionable_tag)

                    logger.debug("tagged_actionable_item %s, created: %s" % (tagged_actionable_item.pk,created))

                elif action_flag == ActionableTaggingHistory.REMOVE:
                    tagged_actionable_item = TaggedActionableItem.objects.filter(tag_id=actionable_tag.id,
                                                                              object_id=pk,
                                                                              content_type=CONTENT_TYPE_OF_THINGS_TO_TAG)

                    if tagged_actionable_item:
                        tagged_actionable_item.delete()
                        affected_tags.add(actionable_tag)

                    if actionable_tag.name == actionable_tag.context.name:
                        # This tag marks an context and the whole context is deleted:
                        # We therefore need to remove all tags in the context
                        tagged_actionable_items = TaggedActionableItem.objects.filter(tag__context=actionable_tag.context,
                                                                                     object_id=pk,
                                                                                     content_type=CONTENT_TYPE_OF_THINGS_TO_TAG)

                        for tagged_actionable_item in tagged_actionable_items:
                            affected_tags.add(tagged_actionable_item.tag)
                            tagged_actionable_item.delete()

            logger.debug("Updating history")
            ActionableTaggingHistory.bulk_create_tagging_history(action_flag,
                                                                 affected_tags,
                                                                 [pk],
                                                                 thing_to_tag_model,
                                                                 user,
                                                                 comment)
            logger.debug("History updated")
        if not supress_transfer_to_dingos and CONTENT_TYPE_OF_THINGS_TO_TAG == ContentType.objects.get_for_model(SingletonObservable):
            update_and_transfer_tag_action_to_dingos(action,
                                                     context_name_set,
                                                     thing_to_tag_pks,
                                                     user=user,
                                                     comment=comment)

        if CONTENT_TYPE_OF_THINGS_TO_TAG == ContentType.objects.get_for_model(SingletonObservable):
            singletons = SingletonObservable.objects.filter(pk__in=thing_to_tag_pks)

            for singleton in singletons:
                actionable_tag_list_repr = list(singleton.actionable_tags.names())
                actionable_tag_list_repr.sort()

                updated_tag_info = ",".join(actionable_tag_list_repr)

                singleton.actionable_tags_cache = updated_tag_info

                logger.debug("For singleton with pk %s found tags %s" % (singleton.pk,updated_tag_info))

                singleton.save()


class TaggedActionableItem(GenericTaggedItemBase):
    tag = models.ForeignKey(ActionableTag,
                            related_name="%(app_label)s_%(class)s_items")

    class Meta:
        verbose_name = _("TaggedActionableItem")
        verbose_name_plural = _("TaggedActionableItems")


class Action(models.Model):

    user = models.ForeignKey(User,
                             # We allow this to be null to mark
                             # actions carried out by the system
                             null=True)

    comment = models.TextField(blank=True)

    class Meta:
        unique_together = ('user','comment')



class EntityType(models.Model):
    name = models.CharField(max_length=256,unique=True)

    objects = models.Manager()
    cached_objects = CachingManager()



class STIX_Entity(models.Model):

    entity_type = models.ForeignKey(EntityType)
    iobject_identifier = models.ForeignKey(Identifier,
                                           null=True,
                                           )
    non_iobject_identifier = models.CharField(max_length=256,
                                              blank=True)

    essence = models.TextField(blank=True)


    def read_essence(self):
        return json.loads(self.essence)

    def __unicode__(self):
        return "%s: %s" % (self.entity_type.name, self.essence)

    class Meta:
        unique_together = ('iobject_identifier','non_iobject_identifier')

class Source(models.Model):

    outdated = models.BooleanField(default=False)

    timestamp = models.DateTimeField(auto_now_add=True, blank=True)

    # If the source is MANTIS, we populate the following fields:

    iobject_identifier = models.ForeignKey(Identifier,
                                           null=True,
                                           related_name = 'actionable_thru')

    iobject = models.ForeignKey(InfoObject,
                                null=True,
                                related_name='actionable_thru')

    iobject_fact = models.ForeignKey(Fact,
                                     null=True,
                                     related_name='actionable_thru')

    iobject_factvalue = models.ForeignKey(FactValue,
                                          null=True,
                                          related_name='actionable_thru')



    top_level_iobject_identifier = models.ForeignKey(Identifier,
                                                     null=True,
                                                     related_name='related_actionable_thru')

    top_level_iobject = models.ForeignKey(InfoObject,
                                          null=True,
                                          related_name='related_actionable_thru')



    related_stix_entities = models.ManyToManyField(STIX_Entity)


    # If the source is a manual import, we reference the Import Info

    import_info = models.ForeignKey("ImportInfo",
                                    null=True,
                                    related_name = 'actionable_thru')

    # Classification of origin

    ORIGIN_UNKNOWN = 0
    ORIGIN_EXTERNAL = 10
    ORIGIN_PUBLIC = 10
    ORIGIN_VENDOR = 20
    ORIGIN_PARTNER = 30
    ORIGIN_INTERNAL = 40

    ORIGIN_KIND = ((ORIGIN_UNKNOWN, "Origin unknown"),
                   (ORIGIN_EXTERNAL, "Origin external, but provenance uncertain"),
                   (ORIGIN_PUBLIC, "Origin public"),
                   (ORIGIN_VENDOR, "Provided by vendor"),
                   (ORIGIN_PARTNER, "Provided by partner"),
    )

    origin = models.SmallIntegerField(choices=ORIGIN_KIND)

    # Classification of processing

    PROCESSING_UNKNOWN = 0
    PROCESSED_AUTOMATICALLY = 10
    PROCESSED_MANUALLY = 20

    PROCESSING_KIND = ((PROCESSING_UNKNOWN, "Processing uncertain"),
                      (PROCESSED_AUTOMATICALLY, "Automatically processed"),
                      (PROCESSED_MANUALLY, "Manually processed"),
    )

    processing = models.SmallIntegerField(choices=PROCESSING_KIND,default=PROCESSING_UNKNOWN)


    TLP_UNKOWN = 0
    TLP_WHITE = 40
    TLP_GREEN = 30
    TLP_AMBER = 20
    TLP_RED = 10

    TLP_KIND = ((TLP_UNKOWN,"Unknown"),
                (TLP_WHITE,"White"),
                (TLP_GREEN,"Green"),
                (TLP_AMBER,"Amber"),
                (TLP_RED,"Red"),
    )

    TLP_MAP = dict(TLP_KIND)

    TLP_RMAP = dict(map(lambda x: (x[1].lower(),x[0]),TLP_KIND))

    TLP_COLOR_CSS = {
        TLP_UNKOWN : "gray",
        TLP_WHITE : "white",
        TLP_GREEN : "green",
        TLP_AMBER : "amber",
        TLP_RED : "red"
    }

    tlp = models.SmallIntegerField(choices=TLP_KIND,
                                   default=TLP_UNKOWN)

    url = models.URLField(blank=True)


    # Sources can be linked to different models:
    # - singleton Observables
    # - IDS Signatures

    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()
    yielded = generic.GenericForeignKey('content_type', 'object_id')

    class Meta:
        unique_together = ('iobject_identifier','iobject_fact','iobject_factvalue','top_level_iobject_identifier','import_info','content_type','object_id')



INF_TIME = datetime.max.replace(tzinfo=timezone.utc)
NULL_TIME = datetime.min.replace(tzinfo=timezone.utc)

def get_inf_time():

    return INF_TIME

def get_null_time():

    return NULL_TIME

class Status(models.Model):

    false_positive = models.NullBooleanField(help_text = "If true, the associated information (usually a "
                                                         "singleton observable) is regarded as false positive"
                                                         "and never used for detection, no matter what the "
                                                         "other status fields say")


    active = models.BooleanField(default = True,
                                 help_text = "If true, the associated information is to be used for detection")

    active_from = models.DateTimeField(default = get_null_time)
    active_to = models.DateTimeField(default = get_inf_time)

    #Field to store tags, seperated by ',', when Django 1.8 released replaced by ArrayField
    #https://docs.djangoproject.com/en/dev/ref/contrib/postgres/fields
    tags = models.TextField(blank=True,default='')

    PRIORITY_UNCERTAIN = 0
    PRIORITY_LOW = 10
    PRIORITY_MEDIUM = 20
    PRIORITY_HIGH = 30
    PRIORITY_HOT = 40


    PRIORITY_KIND = ((PRIORITY_UNCERTAIN, "Uncertain"),
                     (PRIORITY_LOW, "Low"),
                     (PRIORITY_MEDIUM, "Medium"),
                     (PRIORITY_HIGH, "High"),
                     (PRIORITY_HOT, "Hot"),
    )

    priority = models.SmallIntegerField(choices=PRIORITY_KIND,
                                      help_text = "If set to uncertain, it is up to the receiving system"
                                                  "to derive a priority from the additional info provided"
                                                  "in the source information.")

    TLP_UNKOWN = 0
    TLP_WHITE = 40
    TLP_GREEN = 30
    TLP_AMBER = 20
    TLP_RED = 10

    TLP_KIND = ((TLP_UNKOWN,"Unknown"),
                (TLP_WHITE,"White"),
                (TLP_GREEN,"Green"),
                (TLP_AMBER,"Amber"),
                (TLP_RED,"Red"),
    )

    TLP_MAP = dict(TLP_KIND)

    TLP_RMAP = dict(map(lambda x: (x[1].lower(),x[0]),TLP_KIND))

    most_permissive_tlp = models.SmallIntegerField(choices=TLP_KIND,
                                                   default=TLP_UNKOWN)

    most_restrictive_tlp = models.SmallIntegerField(choices=TLP_KIND,
                                                    default=TLP_UNKOWN)



    CONFIDENCE_UNKOWN = 0
    CONFIDENCE_LOW = 10
    CONFIDENCE_MEDIUM = 20
    CONFIDENCE_HIGH = 30


    CONFIDENCE_KIND = ((CONFIDENCE_UNKOWN,"Unknown"),
                (CONFIDENCE_LOW,"Low"),
                (CONFIDENCE_MEDIUM,"Medium"),
                (CONFIDENCE_HIGH,"High"),
    )

    CONFIDENCE_MAP = dict(CONFIDENCE_KIND)
    CONFIDENCE_RMAP = dict(map(lambda x: (x[1].lower(),x[0]),CONFIDENCE_KIND))

    max_confidence = models.SmallIntegerField(choices=CONFIDENCE_KIND,
                                             default=CONFIDENCE_UNKOWN)

    #Field to store kill_chain_phases, seperated by ',', when Django 1.8 released replaced by ArrayField
    #https://docs.djangoproject.com/en/dev/ref/contrib/postgres/fields
    kill_chain_phases = models.TextField(blank=True,default='')


    PROCESSING_UNKNOWN = 0
    PROCESSED_AUTOMATICALLY = 10
    PROCESSED_MANUALLY = 20

    PROCESSING_KIND = ((PROCESSING_UNKNOWN, "Unknown"),
                      (PROCESSED_AUTOMATICALLY, "Automated"),
                      (PROCESSED_MANUALLY, "Manual"),
    )

    PROCESSING_MAP = dict(PROCESSING_KIND)
    PROCESSING_RMAP = dict(map(lambda x: (x[1].lower(),x[0]),PROCESSING_KIND))

    best_processing = models.SmallIntegerField(choices=PROCESSING_KIND,default=PROCESSING_UNKNOWN)




class Status2X(models.Model):

    action = models.ForeignKey(Action,
                                related_name='status_thru')

    status = models.ForeignKey(Status,
                               related_name = 'actionable_thru')

    active = models.BooleanField(default=True)

    timestamp = models.DateTimeField(auto_now_add=True, blank=True)


    # Status can be linked to different models:
    # - singleton Observables
    # - IDS Signatures

    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()
    marked = generic.GenericForeignKey('content_type', 'object_id')

    def __unicode__(self):
        return "Status2X: id %s, active %s, status_id %s, marked_id %s" % (self.id,self.active,self.status_id,self.marked.id)

    class Meta:
        unique_together=('action','status','timestamp')


class SingletonObservableType(models.Model):
    name = models.CharField(max_length=255,unique=True)
    description = models.TextField(blank=True)

    objects = models.Manager()
    cached_objects = CachingManager()


    def __unicode__(self):
        return "%s" % (self.name)



class SingletonObservableSubtype(models.Model):
    name = models.CharField(max_length=255,blank=True,unique=True)
    description = models.TextField(blank=True)

    objects = models.Manager()
    cached_objects = CachingManager()


    def __unicode__(self):
        return "%s" % (self.name)


class SingletonObservable(models.Model):
    type = models.ForeignKey(SingletonObservableType)
    subtype = models.ForeignKey(SingletonObservableSubtype)
    value = models.CharField(max_length=2048)

    status_thru = generic.GenericRelation(Status2X,related_query_name='singleton_observables')

    sources = generic.GenericRelation(Source,related_query_name='singleton_observables')

    actionable_tags = TaggableManager(through=TaggedActionableItem,manager=ActionableTaggableManager)

    mantis_tags = models.TextField(blank=True,default='')

    actionable_tags_cache = models.TextField(blank=True,default='')

    ids_signature = models.ForeignKey("IDSSignature",
                                      null=True)

    class Meta:
        unique_together = ('type', 'subtype', 'value')

    def __unicode__(self):
        return "(%s/%s):%s" % (self.type.name,self.subtype.name,self.value)


    def add_ids_signature(self,signature_text):
        signature_object, created = IDSSignature.objects.get_or_create(content=signature_text)
        print "Sig obj %s" % signature_object.pk
        print "IDS Sig id %s" % self.ids_signature_id
        if (not (signature_object.pk == self.ids_signature_id)):
            print "Creating history"
            IDSSignatureRevision.objects.create(
                                               singleton = self,
                                               ids_signature = signature_object)

        self.ids_signature = signature_object
        self.save()




    def update_status(self,update_function,action=None,user=None,**kwargs):
        # The content type must be defined here: defining it outside the function
        # leads to a circular import
        CONTENT_TYPE_SINGLETON_OBSERVABLE = ContentType.objects.get_for_model(SingletonObservable)
        try:
            # There should already be a status associated with the
            # singleton observable -- we extract that and
            # call the update function


            new_status = None
            status2x = Status2X.objects.get(content_type=CONTENT_TYPE_SINGLETON_OBSERVABLE,
                                            object_id=self.id,
                                            active=True)

            status = status2x.status

            new_status,created = update_function(status=status,
                                                 **kwargs)

            if not created:
                logger.debug("Status %s found" % (status))
            else:
                logger.debug("New status %s derived" % (new_status))


        except ObjectDoesNotExist:
            # This should not happen, but let's guard against it anyhow
            logger.info("No status found, I create one.")
            status, _ = update_function(status=None,**kwargs)
            if not action:
                action,action_created = Action.objects.get_or_create(user=user,comment="Status update called")
            status2x = Status2X(action=action,status=status,active=True,timestamp=timezone.now(),marked=self)
            status2x.save()
            created = False
        except MultipleObjectsReturned:
            # This should not happen either, but let's guard against it
            logger.critical("Multiple active status2x objects returned: I take the most recent status2x object.")
            status2xes = Status2X.objects.filter(content_type=CONTENT_TYPE_SINGLETON_OBSERVABLE,
                                                 object_id=self.id,
                                                 active=True).order_by('-timestamp')
            status2x = status2xes[0]

            status2xes.update(active=False)

            status2x.active=True
            status2x.save()

            status = status2x.status

            new_status,created = update_function(status=status,
                                                 **kwargs)



        if created or (new_status and new_status.id != status.id):
            logger.debug("Updating status")

            status2x.active = False
            status2x.save()
            if not action:
                action,action_created = Action.objects.get_or_create(user=user,comment="Tag addition or removal")
            status2x_new  = Status2X(action=action,status=new_status,active=True,timestamp=timezone.now(),marked=self)
            status2x_new.save()



class SignatureType(models.Model):
    name = models.CharField(max_length=255,unique=True)

class IDSSignature(models.Model):
    content = models.TextField(blank=True)

    import_list = models.ManyToManyField(SingletonObservable,
                                       through="IDSSignatureRevision",
                                       )

class IDSSignatureRevision(models.Model):
    """

    """
    timestamp = models.DateTimeField(auto_now_add=True,blank=True)
    singleton = models.ForeignKey(SingletonObservable,related_name='ids_signature_thru')
    ids_signature = models.ForeignKey(IDSSignature,related_name='singleton_thru')

class ImportInfo(models.Model):

    creating_action = models.ForeignKey(Action,
                                        related_name='import_infos')

    # timestamp here means import_timestamp (akin to dingos)
    timestamp = models.DateTimeField(auto_now_add=True, blank=True)

    create_timestamp = models.DateTimeField(auto_now_add=False, blank=True)

    uid = models.SlugField(max_length=255,default="")

    namespace = models.ForeignKey(IdentifierNameSpace)

    uri = models.URLField(blank=True,
                          default="",
                          help_text="""URI pointing to further
                                       information concerning this
                                       import, e.g., the HTML
                                       report of a malware analysis
                                       through Cuckoo or similar.""")

    name = models.CharField(max_length=255,
                            blank=True,
                            default='Unnamed',
                            editable=False,
                            help_text="""Name of the information object, usually auto generated.
                                         from type and facts flagged as 'naming'.""")

    description = models.TextField(blank=True,default="")

    # type crowdstrike actor/report
    TYPE_UNKOWN = 0
    TYPE_BULK_IMPORT = 10
    TYPE_CHOICES = [
        (TYPE_UNKOWN, "Unknown"),
        (TYPE_BULK_IMPORT, "Bulk Import"),
    ]
    type = models.SmallIntegerField(choices=TYPE_CHOICES, default=TYPE_UNKOWN)

    # The field below will be replaced at some point of
    # time by a Relationship to InfoObjects in the Dingos DB.
    # To get started, we write the name directly

    actionable_tags = TaggableManager(through=TaggedActionableItem,manager=ActionableTaggableManager)

    related_stix_entities = models.ManyToManyField(STIX_Entity)

    class Meta:
        unique_together = ('uid', 'namespace')


class Context(models.Model):
    name = models.CharField(max_length=40,unique=True)
    title = models.CharField(max_length=256,blank=True,default='')
    description = models.TextField(blank=True,default='')
    timestamp = models.DateTimeField(auto_now_add=True)
    related_incident_id = models.SlugField(max_length=40,
                                           blank=True,
                                           help_text="Enter here the number of the associated CERT incident")

    # type crowdstrike actor/report
    TYPE_INVESTIGATION = 10
    TYPE_INCIDENT= 20
    TYPE_CERT_INCIDENT= 30
    TYPE_CHOICES = [
        (TYPE_INVESTIGATION, "INVES"),
        (TYPE_INCIDENT, "IR"),
        (TYPE_CERT_INCIDENT, "CERT"),
    ]

    TYPE_MAP = dict(TYPE_CHOICES)

    TYPE_RMAP = dict(map(lambda x: (x[1].lower(),x[0]),TYPE_CHOICES))

    type = models.SmallIntegerField(choices=TYPE_CHOICES, default=TYPE_INVESTIGATION)


    objects = models.Manager()
    cached_objects = CachingManager()

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('actionables_context_view', args=[self.name])


class ActionableTaggingHistory(models.Model):
    ADD = 0
    REMOVE = 1
    ACTIONS = [
        (ADD,'Added'),
        (REMOVE,'Removed')
    ]


    tag = models.ForeignKey(ActionableTag,related_name='actionable_tag_history')

    timestamp = models.DateTimeField(auto_now_add=True)
    action = models.SmallIntegerField(choices=ACTIONS)
    user = models.ForeignKey(User,related_name='actionable_tagging_history',null=True)
    comment = models.TextField(blank=True)

    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()
    tobject = generic.GenericForeignKey('content_type', 'object_id')


    # Status can be linked to different models:
    # - singleton Observables
    # - IDS Signatures

    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField()
    marked = generic.GenericForeignKey('content_type', 'object_id')

    @classmethod
    def bulk_create_tagging_history(cls,action_flag,tags,
                                    thing_to_tag_pks,
                                    thing_to_tag_model=None,
                                    user=None,comment=''):
        # TODO:
        # CONTENT_TYPE_SINGLETON cannot be defined outside this,
        # because it leads to a circular import ...
        CONTENT_TYPE_SINGLETON_OBSERVABLE = ContentType.objects.get_for_model(SingletonObservable)

        #action = getattr(cls,action.upper())

        if not thing_to_tag_model:
            CONTENT_TYPE_OF_THINGS_TO_TAG = ContentType.objects.get_for_model(SingletonObservable)
        else:
            CONTENT_TYPE_OF_THINGS_TO_TAG = ContentType.objects.get_for_model(thing_to_tag_model)


        entry_list = []
        for pk in thing_to_tag_pks:
                entry_list.extend([ActionableTaggingHistory(action=action_flag,user=user,comment=comment,
                                                            object_id=pk,
                                                            content_type=CONTENT_TYPE_OF_THINGS_TO_TAG,
                                                            tag=x) for x in tags])
        ActionableTaggingHistory.objects.bulk_create(entry_list)


class vSObs2Info(models.Model):

    id = models.PositiveIntegerField(primary_key=True)

    type = models.CharField(max_length=255)
    subtype = models.CharField(max_length=255)
    value = models.CharField(max_length=2048)
    actionable_tags_cache = models.TextField()

    referenced_source = models.ForeignKey(Source,
                                          related_name='+',
                                          on_delete=models.DO_NOTHING)
    source_outdated = models.BooleanField()
    source_tlp = models.SmallIntegerField()
    source_timestamp = models.DateTimeField()

    referenced_stix_entity = models.ForeignKey(STIX_Entity,
                                               related_name='+',
                                               on_delete=models.DO_NOTHING)
    stix_entity_type = models.CharField(max_length=256)
    stix_entity_essence = models.TextField()

    top_level_iobject = models.ForeignKey(InfoObject,
                                          related_name='+',
                                          on_delete=models.DO_NOTHING)
    top_level_iobject_identifier = models.ForeignKey(Identifier,
                                                     related_name='+',
                                                     on_delete=models.DO_NOTHING)
    top_level_iobject_identifier_ns_uri = models.CharField(max_length=256)
    top_level_iobject_identifier_uid = models.SlugField(max_length=255)
    top_level_iobject_identifier_latest_name = models.CharField(max_length=255)

    iobject = models.ForeignKey(InfoObject,
                                related_name='+',
                                on_delete=models.DO_NOTHING)
    iobject_identifier = models.ForeignKey(Identifier,
                                           related_name='+',
                                           on_delete=models.DO_NOTHING)
    iobject_identifier_ns_uri = models.CharField(max_length=256)
    iobject_identifier_uid = models.SlugField(max_length=255)
    iobject_identifier_latest_name = models.CharField(max_length=255)

    import_info = models.ForeignKey(ImportInfo,
                                    related_name='+',
                                    on_delete=models.DO_NOTHING)
    import_info_ns_uri = models.CharField(max_length=256)
    import_info_uid = models.SlugField(max_length=255)
    import_info_name = models.CharField(max_length=255)

    status_ts = models.DateTimeField()
    status = models.ForeignKey(Status,
                               related_name='+',
                               on_delete=models.DO_NOTHING)
    status_most_permissive_tlp = models.SmallIntegerField()
    status_max_confidence = models.SmallIntegerField()
    status_best_processing = models.SmallIntegerField()
    status_kill_chain_phases = models.TextField()
    status_most_restrictive_tlp = models.SmallIntegerField()

    class Meta:
        managed = False
        db_table = 'vsobs2info'


