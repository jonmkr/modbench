# ModBench
Benchmarking application for generating and analysing Modbus traffic across a local testbed configuration. Uses network namespaces to separate network interfaces such that measurements can be done on the same host computer for accurate timestamping.

## Usage
 ### Configuring namespace
One of the two interfaces intended for testing must be configured to use a non-default network namespace.
 ```console
 $ sudo ip netns add <NETNS NAME>
 $ sudo ip link set <INTERFACE NAME> netns <NETNS NAME>
 ```

 Once the interface has been set to the newly created namespace, further configuration, such as ip association, must be done from a shell running within the correct scope.

 ```console
$ sudo ip netns exec <NETNS NAME> bash
 ```