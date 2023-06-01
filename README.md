[comment]: # "Auto-generated SOAR connector documentation"
# Brinqa

Publisher: Asurion  
Connector Version: 1.0.1  
Product Vendor: Brinqa  
Product Name: Brinqa GraphQL API  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.0.0  

The query in this app is a query against the Brinqa GraphQL console. There are two direct usages, the first is to put in a singular model name (ie: Asset) to return the attributes that exist under that model. Otherwise, a pluralized version of the model is used (ie: assets, note case sensitivity) in conjunction with a filter string (ie: name = assetName) and a list of return values, space delineated (ie: ip id name risk) to return information, in the case of the example, on an asset with a specific name

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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Brinqa GraphQL API asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | URL to Brinqa
**username** |  required  | string | User to access Brinqa
**password** |  required  | password | Password for User

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[query brinqa](#action-query-brinqa) - Supply data model, filter, and return strings to retrieve information from Brinqa  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'query brinqa'
Supply data model, filter, and return strings to retrieve information from Brinqa

Type: **generic**  
Read only: **False**

Supply a data model to filter on. Then, supply a filter string, such as display = "DISPLAY_NAME" or ipAddresses = "IP_ADDRESS". Finally, supply a return values string, such as name ipv4 ipv6 risk, it is space delineated. This will return the information from the attributes of the return values on the assets specified by the filter. You can supply only a data model and return all the attributes associated with it. To do so, you use the singular form of the model. To utilize the filtering and return, you use the plural form of the model.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**data_model** |  required  | Data model to query | string | 
**filter** |  optional  | Filter on attributes in data model | string | 
**return_values** |  optional  | Attributes to include in return | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.data_model | string |  |  
action_result.parameter.filter | string |  |  
action_result.parameter.return_values | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 