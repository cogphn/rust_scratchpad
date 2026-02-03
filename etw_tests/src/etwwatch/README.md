### what now?

this kind of turned into a spot to test detections for T1574.014

### ... how's that going?

not great :/ 


it's still looking like the easiest way to see this happening is capturing `Microsoft-Windows-Kernel-Process {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` `ImageLoad` events (EID 5), where `ImageCheckSum` is 0. There is some noise and false positives, but this still seems to be the most compact attribute-matching query.







## General Flow 

so I started off looking into what ETW events are available for dotnet events. Using etwxplorer, there were a couple providers I could look into.

![etwexplorer](./doc_img/etw_explorer_search_dotnet.png)

To start, I would pick events that look loke they help detect T1574.014. For example, in provider `Microsoft-Windows-DotNETRuntime`, event id 87: `AppDomainResourceManagementDomainEnter`. 

~~~xml
<event value="87" symbol="AppDomainResourceManagementDomainEnter" version="0" task="AppDomainResourceManagement" opcode="DomainEnter" level="win:Informational" keywords="AppDomainResourceManagementKeyword ThreadingKeyword" template="AppDomainResourceManagementThreadTerminatedArgs" />
~~~

The template it uses is `AppDomainResourceManagementThreadTerminatedArgs`.  That template looks like this:

~~~xml
<template tid="AppDomainResourceManagementThreadTerminatedArgs">
    <data name="ManagedThreadID" inType="win:UInt64" />
    <data name="AppDomainID" inType="win:UInt64" />
    <data name="ClrInstanceID" inType="win:UInt16" />
</template>
~~~

This means that if we capture this event, we can expect three fields: `ManagedThreadID`, `AppDomainID`, `ClrInstanceID`. Currently I'm grabbing the following:

`Microsoft-Windows-DotNETRuntime` : 156, 85, 87, 151
`Microsoft-Windows-DotNETRuntimeRundown`: 157, 158, 159, 187, 151
`Microsoft-Windows-Kernel-Process`: 5, 6, 15
 

To generate events, I'm using: 
 - https://github.com/cogphn/test-appdomain




