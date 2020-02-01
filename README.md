# FirewallProject
This is my solution to the Illumio Firewall coding challenge

#### Introduction

This repository contains the solution to the Illumio Coding Assignment. 
The objective is to implement a Firewall class that can be used to filter network traffic.
More specifically, given the direction, protocol, port and IP address, the Firewall will 
provide a method that decide if a request can be accepted or rejected. The Firewall class will 
provide a constructor that can read a file with a list of predetermined rules and create an internal 
representation. The accept_packet method with take an request and return a Boolean to accept or 
reject the request.

#### Code Design and Algorithms

For this project, I developed my solution using Python version 3.7. I created a Firewall class in 
Python and implemented several helper methods. One of the the key design trade-off was to optimize 
the accept_packet method performance instead of the constructor performance. The reason being that 
the class is initialized only once but the accept_packet method is called at a very high frequency.

With some research, I found a way to convert a quad-dotted IP address to an integer. This enabled 
me to store all four components on a rule as an integer saving significant amount to space (compared 
to storing strings). Having port ranges and IP ranges as integer interval simplified the process 
of finding matching rules.

My initial functional implementation used a linear search over the rule set to find matching 
rules. I then improved this by introducing binary search over rules
that correspond to a single IP address. If nothing is found, then a linear search is performed 
over the rules corresponding to an ip interval where the ip intervals are sorted in order 
of decreasing breadth. 

#### Functional amd Performance Testing

I used Python's unittest framework to test the correctness of the accept_packet method. According 
the specification, the Firewall class must be able work efficiently with upto 1 million rules.
Thus, I implemented a performance testing class to generate very large number of rules and requests.

On a two year old Macbook Pro, I observed the following timing: 1000 requests were processed in 0.8657 seconds 
(or 0.87ms per request).

#### Improvements and Further work

If I have more time, I would investigate more advanced data structures to deal with the overlapping
IP ranges. Some initial research into this topic pointed me in the direction of Interval Trees, 
Segment Tress and kD Trees. I would have liked to spend more time studying and implementing these 
data structures and conduct a performance evaluation. Another approach would be to evaluate 
custom hashing function to map an integer to a range.

I would be interested in working for the Policy Team.
