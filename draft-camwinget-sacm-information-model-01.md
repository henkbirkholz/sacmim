---
title: SACM Information Model
docname: draft-cam-winget-sacm-information-model-01
date: 2016-05-02

ipr: trust200902
area: security
wg: SACM Working Group
kw: Internet-Draft
cat: std

coding: us-ascii
pi:
   toc: yes
   sortrefs: yes
   symrefs: yes
   comments: yes

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: N. Cam-Winget
  name: Nancy Cam-Winget
  org: Cisco Systems
  email: ncamwing@cisco.com
  street: 3550 Cisco Way
  code: '95134'
  city: San Jose
  region: CA
  country: USA

normative:
  RFC2119:
  RFC3635:
  RFC1573:
  # I-D.ietf-sacm-architecture-13:
 
informative:
  RFC7632:
  I-D.ietf-sacm-requirements: sacm-req

--- abstract

This document defines the information elements that are transported between SACM components and their interconnected relationships. The primary purpose of the Secure Automation and Continuous Monitoring (SACM) Information Model is to ensure the interoperability of corresponding SACM data models and addresses the use cases defined by SACM. The information elements and corresponding types are maintained as the IANA "SACM Information Elements" registry.

--- middle

# Introduction #

**replaces Introduction in the WG IM**

The SACM Information Model (IM) serves multiple purposes:

* to ensure interoperability between SACM data models that are used as transport encodings,
* to provide a standardized set of information elements - the SACM Vocabulary - to enable the exchange of content vital to automated security posture assessment, and
* to enable secure information sharing in a scalable and extensible fashion in order to support the tasks conducted by SACM components.

A complete set of requirements imposed on the IM can be found in {{-sacm-req}}. The SACM IM is intended to be used for standardized data exchange between SACM components (data in motion). Nevertheless, the information elements (IE) and their relationships defined in this document can be leveraged to create and align corresponding data models for data at rest.

The information model expresses, for example, target endpoint (TE) attributes, guidance and evaluation results.  The corresponding information elements are consumed and produced by SACM components as they carry out tasks.

The primary tasks that this information model supports (on data, control, and management plane) are:

* TE Discovery
* TE Characterization
* TE Classification
* Collection
* Evaluation
* Information Sharing
* SACM Component Discovery
* SACM Component Authentication
* SACM Component Authorization
* SACM Component Registration

# Requirements notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in RFC
2119, BCP 14 {{RFC2119}}.

# Information Element Examples
The notation used to define the SACM Information Elements (IEs) is based on the IPFIX information model syntax described in FIXME.  However, there are several examples presented throughout the document that use a simplified pseudo-code to illustrate the basic structure. It should be noted that while they include actual names of subjects and attributes as well as values, they are not intended to influence how corresponding SACM IEs should be defined in {{Information Element Vocabulary}}. The examples are provided for demonstration purposes only. 

# Information Elements

**to be inserted between section 2 and section 3**

The IEs defined in this document comprise the building blocks by which all SACM Content is composed. They are consumed and provided by SACM components on the data plane. Every information element has a unique label: its name. Every type of IE defined by the SACM IM is registered as a type at the IANA registry. The Integer Index of the IANA SMI number tables can be used by SACM data models.

## Context of Information Elements

The IEs in this information model represent information related to the following areas (based on the use cases described in {{RFC7632}}):

* Endpoint Management
* Software Inventory Management
* Hardware Inventory Management
* Configuration Management
* Vulnerability Management

## Extensibility of Information Elements

A SACM data model based on this information model MAY include additional information elements that are not defined here. The labels of additional information elements included in different SACM data models MUST NOT conflict with the labels of the information elements defined by this information model, and the names of additional information elements MUST NOT conflict with each other or across multiple data models.  In order to avoid naming conflicts, the labels of additional IEs SHOULD be prefixed to avoid collision across extensions.  The prefix MUST include an organizational identifier and therefore, for example, MAY be an IANA enterprise number, a (partial) name space URI, or an organization name abbreviation.

# Structure of Information Elements

**replaces beginning text of Information Model Framework and 3.1-3.4, will move syntax 3.1.1 and 3.2.1 to aggregated sub-section, will also privacy sub-section 3.5 and label sub-section 3.6**

A SACM data model based on this information model MAY include additional information elements that are not defined here. The labels of additional information elements included in different SACM data models MUST NOT conflict with the labels of the information elements defined by this information model, and the names of additional information elements MUST NOT conflict with each other or across multiple data models.  In order to avoid naming conflicts, the labels of additional IEs SHOULD be prefixed to avoid collision across extensions.  The prefix MUST include an organizational identifier and therefore, for example, MAY be an IANA enterprise number, a (partial) name space URI or an organization name abbreviation.
VIER
There are two basic types of IEs:

* Attributes: an instance of an attribute type is the simplest IE structure comprised of a unique attribute name and an attribute value (attributes are listed in Section {{Attributes}}.

* Subjects: a subject is a richer structure that has a unique subject name and one or more attributes or subjects (subjects are listed in Section {{Subjects}}. In essence, instances of a subject type are defined (and differentiated) by the attribute values and subjects associated with it.

The notation the SACM IM is defined in is based on the IPFIX information model syntax described in FIXME. The examples presented in this section use simplified pseudo-code to illustrate the basic structure.

Example: an instance of an attribute and an instance of a subject

~~~~ pseudo-code

hostname = "arbutus"

coordinates = (
  latitude = N27.99619,
  longitude = E86.92761
)

~~~~

In general, every piece of information that enables security posture assessment or further enriches the quality of the assessment process can be associated with metadata. In the SACM IM, metadata is represented by specific subjects and is bundled with other attributes or subjects to provide additional information about them. The IM explicitly defines two kinds of metadata: metadata focusing on the data origin (the SACM component that provides the information to the SACM domain) and metadata focusing on the data source (the target endpoint that is assessed). Metadata can also include relationships that refer to other associated IEs (or SACM content in general) by using referencing labels that have to be included in the metadata of the associated IE.

Subjects can be nested and the SACM IM allows for circular or recursive nesting. The association of IEs via nesting results in a tree-like structure wherein subjects compose the root and intermediary nodes and attributes the leaves of the tree. This semantic structure does not impose a specific structure on SACM data models regarding data in motion or data repository schemata for data at rest.

The SACM IM provides two top-level subjects that are used to ensure a homogeneous structure for SACM content and its associated metadata: SACM statements and SACM content-elements. Every set of IEs that is provided by a SACM component in order to be consumed by another SACM component uses these top-level subjects.

## SACM Content Elements

Every piece of information that is provided by a SACM component is always associated  with a set of metadata, for example, the timestamp at which this set of information was produced (e.g. by a collection task) or what target endpoint this set of information is about (e.g. the data-source or a target endpoint identifier, respectively). The subject that associates content IE with content-metadata IE is called a content-element. Content metadata can also include relationships that express associations with other content-elements.

Example: a set of IEs associated with a timestamp and a target endpoint label 

~~~~ pseudo-code

content-element = (
  content-metadata = (
    collection-timestamp = 146193322,
    data-source = fb02e551-7101-4e68-8dec-1fde6bd10981
  ),
  hostname = "arbutus",
  coordinates = (
    latitude = N27.99619,
    longitude = E86.92761
  )
)

~~~~

## SACM Statements

SACM Statements

One or more SACM content elements are bundled in a SACM statement. In contrast to content-metadata, statement-metatdata focuses on the providing SACM component instead of the target endpoint that the content is about. The only content-specific metadata included in the SACM statement is the content-type IE. Therefore, multiple content-elements that share the same statement metadata and are of the same content-type can be included in a single SACM statement.
A SACM statement functions similar to an envelope or a header. Its purpose is to enable the tracking of the origin of data inside a SACM domain and more importantly to enable the mitigation of conflicting information that my originate from different SACM components. How a consuming SACM component actually deals with conflicting information is out-of-scope of the SACM IM. Semantically, the term statement implies that the SACM content provided by a SACM component might not be correct in every context, but rather is the result of an best-effort to produce correct information.

Example: A simple SACM statement including a single content-element.

~~~~ pseudo-code

sacm-statement = (
  statement-metadata = (
    publish-timestamp = 1461934031,
    data-origin = 24e67957-3d31-4878-8892-da2b35e121c2,
    content-type = observation
  ),
  content-element = (
    content-metadata = (
      collection-timestamp = 146193322,
      data-source = fb02e551-7101-4e68-8dec-1fde6bd10981
    ),
    hostname = "arbutus"
  )
)

~~~~

Example: Conflicting information originating from different SACM components.

~~~~ pseudo-code

sacm-statement = (
  statement-metadata = (
    publish-timestamp = 1461934031,
    data-origin = 24e67957-3d31-4878-8892-da2b35e121c2
    content-type = observation
  ),
  content-element = (
    content-metadata = (
      collection-timestamp = 146193322,
      data-source = fb02e551-7101-4e68-8dec-1fde6bd10981
    ),
    coordinates = (
      latitude = N27.99619,
      longitude = E86.92761
    )
  )
)

sacm-statement = (
  statement-metadata = (
    publish-timestamp = 1461934744,
    data-origin = e42885a1-0270-44e9-bb5c-865cf6bd4800,
    content-type = observation
  ),
  content-element = (
    content-metadata = (
      collection-timestamp = 146193821,
      te-label = fb02e551-7101-4e68-8dec-1fde6bd10981
    ),
    coordinates = (
      latitude = N16.67622,
      longitude = E141.55321
    )
  )
)

~~~~

## Relationship Types

An IE can be associated with another IE, e.g. a user-name attribute can be associated with a content-authorization subject. These references are expressed via the relationships subject, which can be included in a corresponding content-metadata subject. The relationships subject includes a list of one or more references.
The SACM IM does not enforce a SACM domain to use unique identifiers as references. Therefore, there are at least two ways to reference another content-element:

* the value of a reference represents a specific content-label that is unique in a SACM domain (and has to be included in the corresponding content-element metadata in order to be referenced), or
* the reference is a subject that includes an appropriate number of IEs in order to identify the referenced content-element by its actual content.

It is recommended to provide unique identifiers in a SACM domain and the SACM IM provides a corresponding naming-convention as a reference in section FIXME. 
The alternative highlighted above summarizes a valid approach that does not require unique identifiers and is similar to the approach of referencing target endpoints via identifying attributes included in a characterization record (FIXME REF arch).

Example: an instance of a content-element subject associated with another subject via its content metadata.

~~~~ pseudo-code

content-element = (
  content-metadata = (
    collection-timestamp = 1461934031,
    te-label = fb02e551-7101-4e68-8dec-1fde6bd10981
    relationships = (
      associated-with-user-account = f3d70ef4-7e18-42af-a894-8955ba87c95d
    )
  ),
  hostname = "arbutus"
)

content-element = (
  content-metadata = (
    content-label = f3d70ef4-7e18-42af-a894-8955ba87c95d
  ),
  user-account = (
    username = romeo
    authentication = local
  )
)

~~~~

## Events

Event subjects provide a structure to represent the change of IE values that was detected by a collection task at a specific point of time. It is mandatory to include the new values in an event subject and it is recommended to include the past values that were replaced by the new IE values. Every event can be associated with a subject-specific event-timestamp and a lastseen-timestamp that might differ from the corresponding collection-timestamps. If these are omitted the collection-timestamp that is included in the content-metadata subject is used instead.

Example: A SACM statement containing an event.

~~~~ pseudo-code

sacm-statement = (
  statement-metadata = (
    publish-timestamp = 1461934031,
    data-origin = 24e67957-3d31-4878-8892-da2b35e121c2,
    content-type = event
  ),
  event = (
    event-attributes = (
      event-name = "host-name change",
    content-element = (
      content-metadata = (
        collection-timestamp = 146193322,
        data-source = fb02e551-7101-4e68-8dec-1fde6bd10981,
        event-component = past-state
      ),
      hostname = "arbutus"
    ),
    content-element = (
      content-metadata = (
        collection-timestamp = 146195723,
        data-source = fb02e551-7101-4e68-8dec-1fde6bd10981,
        event-component = current-state
      ),
      hostname = "lilac"
    )
  )
)

~~~~

# Information Element Vocabulary

**to be inserted in section 5 as candidates**

The vocabulary of IE names standardized by the SACM IM does not prescribe the use of these exact same names in every SACM data model. If terms diverge, a mapping has to be provided in the corresponding SACM data model document.

A subset of the names of the IEs defined in this document are appended with "-type". This indicates that the IM defines a set of values for these IEs (e.g. the interface types defined by the IANA registry or the relationship types).

## Vocabulary of Categories

Categories are special IEs that enable to refer to multiple types of IE via just one name. Therefore, they are similar to a type-choice. A prominent example of a category is network-address. Network-address is a category that every kind of network address is associated with, e.g. mac-address, ipv4-address, ipv6-address, or typed-network-address. If a subject includes network-address as one of its components, any of the category members are valid to be used in its place.

Another prominent example is EndpointIdentifier. Some IEs can be used to identify (and over time re-recognize) target endpoints - those are associated with the category endpoint-identifier.

### Information Element Typing and Taxonomic Relationships
When defining a new IE there are two approaches that can be taken. The first is to provide a specific datatype for the IE that binds the value of that IE to a specific lexical and value space. An example of this would be to define a timestamp IE that has a datatype of unsigned integer that represents the seconds since the UNIX epoch. The other approach is to use a category to define a taxnomic relationship that binds an IE to a set of other IEs that may have distinct lexical and value spaces. An example of this would be to define a timestamp category that contains a publication timestamp, observation timestamp, collection timestamp, storage timestamp, etc. each of which can have their own lexical and value space. Then, when the IE is used, the appropriate IE can be selected based on the data being represented.

content:

: This is a very broad category. Content is the payload of a content element in a SACM statement. Formally, metadata is the complement to content and everything that is not part of SACM statement metadata or content element metadata is therefore considered to be content. Every IE can be content (although the same type of IE can be used in the metadata at the same time - and those would not be content as described before). Annotating every IE with this category would be highly redundant and is therefore omitted for brevity.

network-address: (work-in-progress)

: ipv4-address

: ipv6-address

: mac-address

endpoint-identifier: (work-in-progress)

software-component: (work-in-progress)

software-label: (work-in-progress)

## Vocabulary of Attributes {#Attributes}

The content of every attribute is expressed in a single value. If an alternative representation via a subject is also defined by the SACM IM, the names of both variants are distinguished by a prefixed "a." and "s." (e.g. a.timestamp and s.timestamp).

access-privilege-type:

: a set of types that represents access privileges (e.g. read, write, none)

account-name:

: a label that uniquely identifies an account that can require some form of (user) authentication to access

a.administrative-domain:

: a label the is supposed to uniquely identify an administrative domain

address-association-type:

: a set of types that defines the type of address associations (e.g. broadcast-domain-member-list, ip-subnet-member-list, ip-mac, shared-backhaul-interface, etc.)

address-mask-value:

: a value that expresses a generic address subnetting bitmask

address-type:

: a set of types that specifies the type of address that is expressed in an address subject (e.g. ethernet, modbus, zigbee)

address-value:

: a value that expresses a generic network address

: Category: network-address

application-component:

: a label that references a "sub"-application that is part of the application (e.g. an add-on, a chiper-suite, a library)

: Category: software-component

application-label:

: a label that is supposed to uniquely reference an application

: Category: software-label

application-type:

: a set of types (FIXME maybe a finite set is not realistic here - value not enumerator?) that identifies the type of (user-space) application (e.g. text-editor, policy-editor, service-client, service-server, calender, rouge-like RPG)

: Category: software-type

application-manufacturer:

: the name of the vendor that created the application

: Category: software-manufacturer

application-name:

: a value that represents the name of an application given by the manufacturer

application-version:

: a version string that identifies a specific version of an application

: Category: software-version

authenticator:

: a label that references a SACM component that can authenticate target endpoints (can be used in a target-endpoint subject to express that the te was authenticated by that SACM component)

attribute-name:

: a value that can express the attribute name of generic Attribute-Value-Pair subject

attribute-value:

: a value that can express the attribute value of generic Attribute-Value-Pair subject

authentication-type:

: a set of types that expresses which type of authentication was used to enable a network interaction/connection

birthdate:

: a label for the registered day of birth of a natural person (e.g. the date of birth of a person as an ISO date string http://rs.tdwg.org/ontology/voc/Person#birthdate)

bytes-received:

: a value that represents a number of octets received on a network interface

bytes-sent:

: a value that represents a number of octets sent on a network interface

certificate:

: a value that expresses a certificate that can be collected from a target endpoint

: Category: endpoint-identifier

collection-task-type:

: a set of types that defines how collected SACM content was acquired (e.g. network-observation, remote-acquisition, self-reported)

confidence:

: a representation of the subjective probability that the assessed value is correct.  If no confidence value is given it is assumed that the confidence is 1 (limits confidence values to the range between zero and one)

content-action:

: a set of types that expresses a type of action (e.g. add, delete, update). Can be associated, for instance, with an event subject or with an network observation

content-elements:

: a value that represents the number of content-elements included in a SACM statement

content-topic:

: a set of types that defines what kind of concept the information is included in a content element (e.g. Session, User, Interface, PostureProfile, Flow, PostureAssessment, TargetEndpoint)

content-type:

: a set of types that defines what kind of information is included in a content element (e.g. EndpointConfiguration, EndpointState, DirectoryEntry, Event, Incident)

country-code:

: a set of types according to ISO 3166-1 trigraphic codes of countries

data-origin:

: a label that uniquely identifies a SACM component in and across SACM domains

: Aliases: sacm-component-id

a.data-source:

: a label that is supposed to uniquely identify the data source (e.g. a target endpoint or sensor) that provided an initial endpoint attribute record

: Aliases: te-id (work-in-progress)

decimal-fraction-denominator:

: a denominator value to express a decimal fraction time stamp (e.g. in s.timestamp)

decimal-fraction-numerator:

: a numerator value to express a decimal fraction time stamp (e.g. in s.timestamp)

default-depth:

: a value that expresses how often a circular reference of subject is allowed to repeat, or how deep a recursive nesting may occour, respectively.

discoverer:

: a label that refers to the SACM component that discovered a target endpoint (can be used in a target-endpoint subject to express, for example, that the te was authenticated by that SACM component)

email-address:

: a value that expresses an email-address

event-type:

: a set of types that define the categories of an event (e.g. access-level-change, change-of-priviledge, change-of-authorization, environmental-event, or provisioning-event)

event-threshold:

: if applicable, a value that can be included in an event subject to indicate what numeric threshold value was crossed to trigger that event

event-threshold-name:

: if an event is created due to a crossed threshold, the threshold might have a name associated with it that can be expressed via this value

event-trigger:

: this value is used to express more complex trigger conditions that may cause the creation of an event.

firmware-id:

: a label that represents the BIOS or firmware ID of a specific target endpoint

: Category: endpoint-identifier

hardware-serial-number:

: a value that identifies a piece of hardware that is a component of a composite target endpoint (in essence, every target endpoint is a composite) and can be acquired from a target endpoint by a collection task

: Category: endpoint-identifier

host-name:

: a label typically associated with an endpoint but not always intended to be unique in a given scope

: Category: endpoint-identifier

interface-label:

: a unique label a network interface can be referenced with

ipv6-address-subnet-mask-cidrnot:

: an IPv6 subnet bit mask in CIDR notation

ipv6-address-value:

: an IPv4 address value

: Category: endpoint-identifier, network-address

ipv4-address-subnet-mask-cidrnot:

: an IPv4 subnet bit mask in CIDR notation

ipv4-address-subnet-mask:

: an IPv4 subnet mask

ipv4-address-value:

: an IPv4 address value

: Category: endpoint-identifier, network-address

layer2-interface-type:

: a set of types referenced by IANA ifType

layer4-port-address:

: a layer 4 port address (typically used, for example, with TCP and UDP)

: Category: network-address

layer4-protocol:

: a set of types that express a layer 4 protocol (e.g. UDP or TCP)

location-name:

: a value that represents a named region of space FIXME

mac-address:

: a value that expresses an Ethernet address

: Category: endpoint-identifier, network-address

method-label:

: a label that references a specific method registered and used in a SACM domain (e.g. method to match and re-identify target endpoints via identifying attributes)

method-repository:

: a label that references a SACM component methods can be registered at and that can provide guidance in the form of registered methods to other SACM components

network-access-level-type:

: a set of types that expresses categories of network access-levels (e.g. block, quarantine, etc.) 

network-id:

: most networks, such as AS, an OSBF domains, or vlans, can have an ID that is represented via this attribute.

network-interface-name:

: a label that uniquely identifies an interface associated with a distinguishable endpoint

network-layer:

: a set of layers that express the specific network layer an interface operate on (typically layer 2-4)

network-name:

: a label that is associated with a network. Some networks, for example effective layer2-broadcast-domains, are difficult to "grasp" and therefore quite complicated to name

organization-id:

: a label that is supposed to uniquely identify an organization

organization-name:

: a value that represents the name of an organization

os-component:

: a label that references a "sub-component" that is part of the operating system (e.g. a kernel module, microcode, or ACPI table)

: Category: software-component

os-label:

: a label that references a specific version of an operating system, including patches and hotfixes

: Category: software-label

os-manufacturer:

: the name of the manufacturer of an operating system

: Category: software-manufacturer

os-name:

: the name of an operating system

: Category: software-name

os-type:

: a set of types that identifies the type of an operating system (e.g. real-time, security-enhanced, consumer, server)

: Category: software-type

os-version:

: a value that represents the version of an operating-system

: Category: software-version

patch-id:

: a label the uniquely identifies a specific software patch

patch-name:

: the vendor's name of a software patch

person-first-name:

: the first name of a natural person

person-last-name:

: the last name of a natural person

person-middle-name:

: the first name of a natural person

phone-number:

: a label that expresses the u.s. national phone number (e.g. pattern value="(\(\d{3}\) )?\d{3}-\d{4}")

phone-number-type:

: a set of types that express the type of a phone number (e.g. DSN, Fax, Home, Mobile, Pager, Secure, Unsecure, Work, Other)

privilege-name:

: the attribute-name of the privilege represented as an AVP

privilege-value:

: the value-content of the privilege represented as an AVP

protocol:

: a set of types that defines specific protocols above layer 4 (e.g. http, https, dns, ipp, or unknown)

public-key:

: the value of a public key (regardless of its method of creation, crypto-system, or signature scheme) that can be collected from a target endpoint

: Category: endpoint-identifier

relationship-content-element-guid:

: a reference to a specific content element used in a relationship subject

relationship-statement-guid:

: a reference to a specific SACM statement used in a relationship subject

relationship-object-label:

: a reference to a specific label used in content (e.g. a te-label or a user-id). This reference is typically used if matching content attribute can be done efficiantly and can also be included in addition to a relationship-content-element-guid reference.

relationship-type:

: a set of types that is in every instance of a relationship subject to highlight what kind of relationship exists between the subject the relationship is included in (e.g. associated_with_user, applies_to_session, seen_on_interface, associated_with_flow, contains_virtual_device)

role-name:

: a label that references a collection of privileges assigned to a specific entity (identity? FIXME)

session-state-type:

: a set of types a discernible session (an ongoing network interaction) can be in (e.g. Authenticating, Authenticated, Postured, Started, Disconnected)

statement-guid:

: a label that expresses a global unique ID referencing a specific SACM statement that was produced by a SACM component

statement-type:

: a set of types that define the type of content that is included in a SACM statement (e.g. Observation, DirectoryContent, Correlation, Assessment, Guidance)

status:

: a set of types that defines possible result values for a finding in general (e.g. true, false, error, unknown, not applicable, not evaluated)

sub-administrative-domain:

: a label for related child domains an administrative domain can be composed of (used in the subject s.administrative-domain)

sub-interface-label:

: a unique label a sub network interface (e.g. a tagged vlan on a trunk) can be referenced with

super-administrative-domain:

: a label for related parent domains an administrative domain is part of (used in the subject s.administrative-domain)

super-interface-label:

: a unique label a super network interface (e.g. a physical interface a tunnel interface terminates on) can be referenced with

te-assessment-state:

: a set of types that defines the state of assessment of a target-endpoint (e.g. in-discovery, discovered, in-classification, classified, in-assessment, assessed)

te-label:

: an identifying label created from a set of identifying attributes used to reference a specific target endpoint

te-id:

: an identifying label that is created randomly, is supposed to be unique, and used to reference a specific target endpoint

: Aliases: data-source

a.timestamp:

: a timestamp the expresses a specific point in time

timestamp-type:

: a set of types that express what type of action or event happened at that point of time (e.g. discovered, classified, collected, published). Can be included in a generic s.timestamp subject

units-received:

: a value that represents a number of units (e.g. frames, packets, cells or segments) received on a network interface

units-sent:

: a value that represents a number of units (e.g. frames, packets, cells or segments) sent on a network interface

username:

: a part of the credentials required to access an account that can be collected from a target endpoint

: Category: endpoint-identifier

user-directory:

: a label that identifies a specific type of user-directory (e.g. ldap, active-directory, local-user)

user-id:

: a label that references a specific user known in a SACM domain

web-site:

: a URI that references a web-site

WGS84-longitude:

: a label that represents WGS 84 rev 2004 longitude

WGS84-latitude:

: a label that represents WGS 84 rev 2004 latitude

WGS84-altitude:

: a label that represents WGS 84 rev 2004 altitude

## Vocabulary of Subjects {#Subjects}

The content of every subject IE is expressed by the mandatory and optional IEs it can be composed of. The components of a subject can have a cardinality associated with them:

* (\*): zero to unbounded occurrences
* (\+): one to unbounded occurrences
* (?): zero or one occurrence
* (m,n): between m and n occurrences
* no cardinality: one occurrence

If there is no cardinality highlighted or the cardinality (\+) or (m,n) is used, including this IE in the subject is mandatory. In contrast, optional IE are expressed via the cardinality (?) or (\*).
An subject can prescribe a strict sequence to the component IEs it contains. This in indicated by an (s).
Subjects that are prefixed with "s." have a simplified attribute counterpart that is prefixed with "a."

address-association (s):

: some addresses are associated with each other, e.g. a mac-address can be associated with a number of IP addresses or a sensor address can be associated with the external address of its two redundant IP gateways. The first address is the address a number of addresses with the same type is associated with. An address type SHOULD be included and the addresses associated with the first address entry MUST be of the same type. NANCY FIXME

: address

: address-type (?)

: address (+)

: address-type (?)

s.administrative-domain:

: this subject is intended to express more complex setups of interconnected administrative domains

: a.administrative-domain

: sub-administrative-domain (\*)

: super-administrative-domain (?)

: location (?)

application:

: an application is software that is not part of the kernel space (therefore typically runs in the user space. An application can depend on specfific running party of an operating system.

: application-label (?)

: application-name

: application-type (\*)

: application-component (\*)

: application-manufacturer (?)

: application-version (?)

application-instance:

: a specific instance of an application that is installed on an endpoint. The application-label is used to refer to corresponding information stored in an application subject

: application-label

: target-endpoint

attribute-value-pair:

: a generic subject that is used to express various AVP (e.g. Radius Attributes)

: attribute-name

: attribute-value 

content-creation-timestamp:

: a decimal fraction timestamp that specifies the point in time the content element was created by a SACM component

: decimal-fraction-denominator

: decimal-fraction-numerator

content-element:

: content produced by a SACM component is encapsulated in content-elements that also include content-metadata regarding that content

: content-metadata (+)

: content (+)

content-metadata:

: metadata regarding the content included in a specific content-element. The content the metadata annotates can be initially collected content - in this case a data-source has to be included in the metadata. Content can also be the product of a SACM component (e.g. an evaluator), which requires a data-origin IE instead that references the producer of information.

: content-element-guid

: content-creation-timestamp

: content-topic

: content-type

: s.data-source (?)

: data-origin (?)

: relationship (\*)

s.data-source:

: a subject that refers to a target endpoint that is the source of SACM content - either via a label (a.data-source, which could also be used without this subject), or via a list of endpoint-identifiers (category). Both can be included at the same time but MUST NOT conflict.

: a.data-source (?)

: endpoint-identifier (\*)

dst-flow-element:

: identifies the destination of a flow. The port number SHOULD be included if the network-address is an IP-address.

: network-address

: layer4-port-address (?) 

ethernet-interface:

: the only two mandatory component of this subject is the mac-address and the generated label (to distinguish non-unique addresses). This acknowledges the fact that in many cases this is the only information available about an Ethernet interface. If there is more detail information available it MUST be included to avoid ambiguity and to increase the usefulness for consumer of information. The exception are sub-interface-labels and super-interface-labels, which SHOULD be included.

: interface-label

: network-interface-name (?)

: mac-address

: network-name (?)

: network-id (?)

: layer2-interface-type (?)

: sub-interface-label (\*)

: super-interface-label (\*)

event (s):

: this a special purpose subject that represents the change of content. As with content-elements basically every content can be included in the two content entries. The mandatory content entry represents the "after" state of the content and the optional content entry can represent the "before" state if available or required.

: event-type (?)

: event-threshold (?)

: event-threshold-name (?)

: event-trigger (?)

: typed-timestamp

: content

: content (?)

flow-record:

: a composite that expresses a single flow and its statistics. If applicable, protocol and layer4-protocol SHOULD be included

: src-flow-element

: dst-flow-element

: protocol (?)

: layer4-protocol (?)

: flow-statistics

flow-statistics:

: this subject aggregates bytes and units send and received

: bytes-received

: bytes-sent

: units-received

: units-sent

group:

: insert text here (work in progress)

ipv4-address:

: an IPv4 address is always associated with a subnet. This subject combines these both tightly nit values. Either a subnet mask or a CIDR notation bitmask SHOULD be included.

: ipv4-address-value

: ipv4-address-subnet-mask-cidrnot (?)

: ipv4-address-subnet-mask (?)

ipv6-address:

: an IPv6 address is always associated with a subnet. This subject combines these both tightly nit values. A CIDR notation bitmask SHOULD be included.

: ipv6-address-value

: ipv6-address-subnet-mask-cidrnot (?)

location:

: a subject that aggregates potential details about a location

: location-name

: WGS84-longitude

: WGS84-latitude

: WGS84-altitude

operation-system:

: an operation-system is software that is directly interacting with the hardware, provides the runtime environment for the user-space and corresponding interfaces to hardware functions.

: os-label (?)

: os-name 

: os-type (\*)

: os-component (\*)

: os-manufacturer (?)

: os-version (?)

organization:

: this subject aggregates information about an organization and can be references via its id

: organization-id

: organization-name

: location (?)

person:

: a subject that aggregates the details about a person and combines it with a identifier unique to SACM domains

: person-first-name

: person-last-name

: person-middle-name (\*)

: phone-contact (\*)

: email-address (\*)

phone-contact:

: this subject can be used to reference a phone number and how it fucntions as a contact

: phone-number

: phone-number-type (?)

priviledge:

: a subject to express priviledges via a specific name/value pair

: privilege-name

: privilege-value

relationship:

: the relationship subject enables to associate the subject it is included in with other subject if they contain a unique identifier or label - providing an alternative to including attributes of other content subject as a means to map them (which remains a valid alternative, though). The relationship subject MUST at least reference one relationship object (either a SACM statement iden HENK/NANCY FIXME - What text goes here?):

: relationship-type

: relationship-content-element-guid (\*)

: relationship-statement-guid (\*)

: relationship-object-label (\*)

sacm-statement:

: every SACM components produces information in this format. This subject can be considered the root IE for every SACM message generated. There MUST be at least one content element included in a SACM statement and if there are more than one, they are ordered in a sequence.

: statement-metadata

: content-element (+)(s)

session:

: represents an ongoing network interaction that can be in various states of authentication or assessement

: session-state-type

: (work-in-progress)

src-flow-element:

: identifies the source of a flow. The port number SHOULD be included if the network-address is an IP-address.

: network-address

: layer4-port-address (?) 

statement-creation-timestamp:

: a decimal fraction timestamp that specifies the point in time the SACM statement was created by a SACM component

: decimal-fraction-denominator

: decimal-fraction-numerator

statement-publish-timestamp:

: a decimal fraction timestamp that specifies the point in time the SACM component attempted to publish the SACM statement (if successful, this will result in the publish-timestamp send with the SACM statement).

: decimal-fraction-denominator

: decimal-fraction-numerator

statement-metadata:

: every SACM statement includes statement metadata about the SACM component it was produced by and a general category that indicates what this statement is about

: statement-guid

: data-origin

: statement-creation-timestamp (?)

: statement-publish-timestamp

: statement-type

: content-elements

target-endpoint:

: This is a central subject used in the process chains a SACM domain can compose. Theoretically, every kind of information can be associated with a target endpoint subject via its corresponding content element. A few select IE can be stored in the subject itself to reduce the overhead of following references that would occur in most scenarios. If the hostname is unknown the value has to be set as an equivalent to "not available" (e.g. NULL). Comment from the authors: This is "work in progress" and a good basis for discussion.

: host-name

: te-label

: s.administrative-domain (?)

: application-instance (\*)

: ethernet-interface (\*)

: address-association (\*)

: s.data-source (?)

: operation-system (?)

te-profile:

: a set of expected states, polisubjects and pieces of guidance that can be matched to a target endpoint (or a class of target endpoints "work in progress")

typed-timestamp:

: a flexible timestamp subject that can express the specific type of timestamp via its content. This is an alternative to the "named" timestamps that do not include a timestamp-type

: decimal-fraction-denominator

: decimal-fraction-numerator

: timestamp-type

user:

: a subject that references details of a specific user known in a SACM domain active on a specific target endpoint

: user-id

: username (?)

: data-source (?)

: user-directory (?)

# Example composition of SACM statements

This section illustrates examples how SACM statements are composed of content elements, how relationship subject can be used in content metadata and gives an impression how the categories statement-type, content-topic and content-type are intended to be used.

The SACM statements instances are written in pseudo code. Attributes end with a colon. Some attributes include exemplary values to, for example, present how references to guid and labels can be used. For the sake of brevity, not all mandatory IE that are part of a subject are always included (e.g. as it is the case with target-endpoint).

The example shows three SACM statements that were produced by three different SACM components that overall include four related content elements.

This is (work in progress).

~~~~~~~ 

sacm statement
  statement-metadata
    statement-guid: example-sguid-one
    data-origin: SACM-component-label-one
    statement-publish-timestamp: exmample-TS-one
    statement-type: Observation
  content-element
    content-metadata
      content-element-guid: example-cguid-one
      content-creation-timestamp:
      content-topic: Flow
      content-type: EndpointState
      relationship
        relationship-type: is-associated-with-user
        relationship-content-object: example-cguid-three
      relationship
        relationship-type: is-associated-with-te
        relationship-content-object: example-cguid-two
      relationship
        relationship-type: is-associated-with-te
        relationship-content-object: example-te-label      
    flow-record
      src-flow-element
        network-address (ipv4-address)
          ipv4-address-value:
          ipv4-address-subnet-mask-cidrnot:
        layer4-port-address: 23111
      dst-flow-element
        network-address (IPv4-address)
          ipv4-address-value:
          ipv4-address-subnet-mask-cidrnot:
        layer4-port-address: 22
      protocol: ssh
      layer4-protocol: tcp
      flow-statistics
        bytes-received:
        bytes-sent:
        units-received:
        units-sent:
  content-element
    content-metadata
      content-element-guid: example-cguid-two
      content-creation-timestamp:
      content-topic: TargetEndpoint
      content-type: EndpointConfiguration
    target-endpoint
      te-label: example-te-label
      host-name: example-host-name
      ethernet-interface: example-interface

sacm statement
  statement-metadata
    statement-guid: example-sguid-two
    data-origin: SACM-component-label-two
    statement-publish-timestamp: exmample-TS-two
    statement-type: DirectoryContent
  content-element
    content-metadata
      content-element-guid: example-cguid-three
      content-creation-timestamp:
      content-topic: User
      content-type: DirectoryEntry
    user
      user-name: example-username
      user-directory: component-id

sacm statement
  statement-metadata
    statement-guid: example-sguid-three
    data-origin: SACM-component-label-three
    statement-publish-timestamp: example-TS-three
    statement-type: Observation
  content-element
    content-metadata
      content-element-guid: example-cguid-four
      content-creation-timestamp:
      content-topic: Priviledges
      content-type: Event
      relationship
        relationship-type: is-associated-with-user
        relationship-content-object: example-cguid-three 
    event
      event-type: change-of-priviledge
      typed-timestamp
        decimal-fraction-denominator:
        decimal-fraction-numerator:
        timestamp-type: time-of-observation
      priviledge
        privilege-name: super-user-escalation
        privilege-value: true
      priviledge
        privilege-name: super-user-escalation
        privilege-value: false

~~~~~~~

#  IANA considerations

This document includes requests to IANA.

#  Security Considerations

#  Acknowledgements

#  Change Log

First version -00

# Contributors

--- back
