+++
title = "Fuzzing Wazuh for Fun, Credits and Profit(?) 1/3"
date = 2023-10-27T14:30:00+02:00
tags = ["pwn,", "fuzzing"]
draft = false
author = "Konstantin Bücheler"
+++

<div class="ox-hugo-toc toc">

<div class="heading">Table of Contents</div>

- [Intro](#intro)
    - [Uni project](#uni-project)
    - [LibAFL](#libafl)
    - [Target criteria](#target-criteria)
- [Short Intro to fuzzing](#short-intro-to-fuzzing)
- [LibAFL](#libafl)
- [Target Introduction](#target-introduction)
- [Target Specific Challenges](#target-specific-challenges)

</div>
<!--endtoc-->



## Intro {#intro}


### Uni project {#uni-project}


### LibAFL {#libafl}


### Target criteria {#target-criteria}


## Short Intro to fuzzing {#short-intro-to-fuzzing}

Fuzzing, or fuzz testing, is a widely used technique in software testing and vulnerability research.
The main concept behind fuzzing is to repeatedly execute a target with changing inputs, while monitoring for crashes.
Inputs that result in a crash are likely to trigger a bug within the target application. This information could potentially
lead to the discovery of a vulnerability, depending on the nature of the bug.

<a id="figure--feedback-fuzzing"></a>

{{< figure src="/images/feedback_fuzzing.png" caption="<span class=\"figure-number\">Figure 1: </span>Feedback Fuzzing" >}}


## LibAFL {#libafl}

Why? How? When?


## Target Introduction {#target-introduction}

Describe wazuh


## Target Specific Challenges {#target-specific-challenges}

Complex State, Multithreading, Chroot, Complex message format
