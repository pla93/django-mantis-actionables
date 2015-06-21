
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

from uuid import uuid4
import autocomplete_light
from .models import Context, TagInfo
from django import forms

from django.forms import widgets

from django.core.validators import RegexValidator

from taggit.models import Tag

from dingos import DINGOS_MANTIS_ACTIONABLES_CONTEXT_TAG_REGEX

from dingos.forms import ResultActionForm

class TagForm(autocomplete_light.ModelForm):
    tag = autocomplete_light.ChoiceField(widget = autocomplete_light.TextWidget('TagInfoAutocompleteActionables'))
    class Meta:
        model = TagInfo


class ContextEditForm(forms.Form):
    def __init__(self,*args,**kwargs):

        self.current_type = kwargs.pop('current_type')
        self.current_name = kwargs.pop('current_name')

        super(ContextEditForm,self).__init__(*args,**kwargs)



    title = forms.CharField(
                            max_length=256,
                            widget=widgets.TextInput(attrs={'size':'100','class':'vTextField'}))
    description = forms.CharField(max_length=4096,widget=widgets.Textarea(attrs={'class':'vTextField'}))

    type = forms.ChoiceField(choices=Context.TYPE_CHOICES)
    related_incident_id = forms.SlugField(max_length=40,required=False,help_text="Enter here the number of the related CERT incident.",
                                          label="CERT Incident Nr.")

    def clean(self):
        cleaned_data = super(ContextEditForm, self).clean()
        type = int(cleaned_data.get("type"))
        related_incident_id = cleaned_data.get("related_incident_id")

        cleaned_data['new_context_name'] = ''

        if type != self.current_type:
            if type == Context.TYPE_CERT_INCIDENT or self.current_type == Context.TYPE_CERT_INCIDENT:
                raise forms.ValidationError("Cannot change a CERT incident to something else!")

            if not self.current_name.startswith(Context.TYPE_MAP[self.current_type]):
                raise forms.ValidationError("Cannot change type because context name '%s' "
                                            "does not signify current context type '%s'" %(self.current_name,
                Context.TYPE_MAP[self.current_type]))
            else:
                new_context_name = "%s%s" % (Context.TYPE_MAP[type],
                                             self.current_name.split(Context.TYPE_MAP[int(self.current_type)])[1])
                existing_contexts = Context.objects.filter(name=new_context_name)

                if existing_contexts:
                    raise forms.ValidationError("Cannot change type and rename, because there already exists a context %s" % new_context_name)

                existing_dingos_tags = Tag.objects.filter(name=new_context_name)
                if existing_dingos_tags:
                    raise forms.ValidationError("Cannot change type and rename, because there already exists a MANTIS tag '%s'" % new_context_name)

                if type == Context.TYPE_INCIDENT and not related_incident_id:
                    raise forms.ValidationError("Please provide an incident number when changing type from investigation to incident.")

                cleaned_data['new_context_name'] = new_context_name
        return cleaned_data


class BulkTaggingForm(ResultActionForm):

    def __init__(self,*args,**kwargs):

        fixed_context = kwargs.pop('fixed_context',None)

        self.action = kwargs.pop('action','').lower()


        super(BulkTaggingForm, self).__init__(*args, **kwargs)

        if fixed_context:

            self.fields['context'] = forms.CharField(initial=fixed_context,
                                                     widget=forms.TextInput(attrs={'readonly':'True'}))
        else:
            self.fields['context'] = forms.CharField()

        self.fields['tags'] = forms.CharField(required= fixed_context,
                                              help_text= """Enter multiple tags separated by commas.
                                              In order to remove the context (and all associated tags),
                                              enter the context itself and press "Remove". """)


    reason = forms.CharField(widget=forms.Textarea(),
                             required=False,
                             help_text="Enter rationale (optional for adding tags, required for deleting).")

    def clean(self):
        cleaned_data = super(BulkTaggingForm, self).clean()

        tags = map(lambda x: x.strip(), cleaned_data['tags'].split(','))

        if self.action and self.action == 'add':
            for tag in tags:
                is_context_tag = False
                for regex in DINGOS_MANTIS_ACTIONABLES_CONTEXT_TAG_REGEX:
                    if regex.match(tag):
                        is_context_tag = True
                        break
                if is_context_tag:
                    self.add_error('tags', forms.ValidationError("You cannot add a context tag within a context!"))



        if self.action and self.action == 'remove':
            if cleaned_data.get('reason','').strip() == '':

                self.add_error('reason', forms.ValidationError("Please enter a reason for removing the tags."))

        return cleaned_data


class BulkSearchForm(forms.Form):
    search_term = forms.CharField(widget=forms.Textarea(), required=True)
    id = forms.CharField(widget=forms.HiddenInput, required=True)

    # CHOICES_MODE = [
    #     ("icontains", "Contains Value"),
    #     ("iexact", "Exact Match")
    # ]
    # search_mode = forms.ChoiceField(choices=CHOICES_MODE, widget=forms.RadioSelect(), required=True)
    #
    # CHOICES_PARSE = [
    #     (True, "Parse Textarea"),
    #     (False, "One Indicator Line by line")
    # ]
    # parse_textfield = forms.ChoiceField(choices=CHOICES_PARSE, widget=forms.RadioSelect(), required=True)


