### ok what am I looking at?

a mini data collector (name pending). It's goal is to enable security researchers to collect Windows system telemetry while replaying threat actor techniques.

### ... but SIEMs exist

I KNOW, but what if you didn't have one? So one time I had to grab some telemetry for a presentation, and my lab was ...between usable states... ; So anyway I knew the attack I wanted to replay, and I knew that the data would normally be really easy to get if I had a SIEM running, but in that moment it seemed really annoying that the shortest path to getting the data I wanted was:
 - provision resources
 - install a SIEM (likely elastic - no shade, elastic is GREAT)
 - configure an agent
 - move the agent over to the victim system, install it and troubleshoot it

I wanted something relatively simple to configure, that would work on freshly installed windows systems, that just kept security telemetry for me while I replay attacks.

### alright man, you do you I guess

I also kind of wanted to get more Rust exposure, so that was a motivator as well. In it's current state, the tool seems to run fine, but every now and again I'll run into strange bugs. I try to fix those as I go. I've been working on it part-time just for fun - if you have any ideas for features or know how to fix any of the billions of existing bugs - I'll be happy to hear those! 

### so you're saying I shouldn't run this in prod?

.....no.......no, friend; 



