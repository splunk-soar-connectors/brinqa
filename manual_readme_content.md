[comment]: # " File: README.md"
[comment]: # "  Copyright (c) Asurion, 2023"
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
# Authentication

This app is configured to authenticate with Username and Password of a Brinqa account with GraphQL
access.

## Setup

The GraphQL console may be off by default in the UI, meaning that there is no way to access it
without a direct link. In order to create a link under an icon, navigate to Navigation Menu under
User Interface, edit the source code there, and include this block under the icon you wish to access
the console through.
`        {        "link": {        "type": "URI",        "href": "/graphql/{appName}/browser",        "target": "_blank"        },        "title": "GraphQL Console",        "visibility": {        "active": true,        "roles": [        *Insert roles able to access the console here*        ]        }        }       `

### Overview of Usage

The query in this app is a query against the GraphQL console. There are two direct usages, the first
is to put in a singular model name (ie: Asset) to return the attributes that exist under that model.
Otherwise, a pluralized version of the model is used (ie: assets, note case sensitivity) in
conjunction with a filter string (ie: name = \*assetName\*) and a list of return values, space
delineated (ie: ip id name risk) to return information, in the case of the example, on an asset with
a specific name
