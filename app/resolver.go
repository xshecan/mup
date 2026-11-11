package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type systemResolver struct{}

func (systemResolver) Resolve(destination netip.Addr, interfaceName string) (netip.Addr, int, error) {
	if !destination.Is4() {
		return netip.Addr{}, 0, errors.New("route destination must be IPv4")
	}
	if interfaceName != "" {
		networkInterface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("find interface %q: %w", interfaceName, err)
		}
		source, err := firstInterfaceIPv4(networkInterface)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		return source, networkInterface.Index, nil
	}

	connection, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, 9)))
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("resolve route to %s: %w", destination, err)
	}
	source := connection.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	_ = connection.Close()
	networkInterface, err := interfaceForAddress(source)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return source, networkInterface.Index, nil
}

func (systemResolver) UpInterfaceIndexes() ([]int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	indexes := make([]int, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp != 0 {
			indexes = append(indexes, networkInterface.Index)
		}
	}
	return indexes, nil
}

func firstInterfaceIPv4(networkInterface *net.Interface) (netip.Addr, error) {
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("list addresses on %s: %w", networkInterface.Name, err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s has no IPv4 address", networkInterface.Name)
}

func interfaceForAddress(address netip.Addr) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for index := range interfaces {
		addresses, err := interfaces[index].Addrs()
		if err != nil {
			continue
		}
		for _, candidate := range addresses {
			prefix, err := netip.ParsePrefix(candidate.String())
			if err == nil && prefix.Addr() == address {
				return &interfaces[index], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns route source %s", address)
}
