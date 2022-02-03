#!/bin/env python3

import sys
import yaml
import re
import os
import math

ip_regex = re.compile(r"\.".join(["([0-9]{1,3})"]*4))
cdir_regex = re.compile("(" + r"\.".join(["[0-9]{1,3}"]*4) + r")/([0-9]{1,2})")
env_var_regex = re.compile("\${([A-Za-z0-9_-]+)}|\$([A-Za-z0-9_-]+)")

def get_dic_error(key: str, cls: str):
    return ValueError("Missing '" + key + "' component of " + cls + " object")

def is_list_of_strings(lst):
    if lst and isinstance(lst, list):
        return all(isinstance(elem, str) for elem in lst)
    return False

class YamlItemBase:
    def __repr__(self):
        return str(self)

class IP(YamlItemBase):
    def __init__(self, ip: str):
        match = ip_regex.fullmatch(ip)

        if match is None:
            raise ValueError("IP format invalid")
        self.ip = str(ip)
        self.part = [0, 0, 0, 0]
        for i in [1, 2, 3, 4]:
            val = int(match.group(i))
            if val < 0 or val > 255:
                raise ValueError("IP format invalid")
            self.part[i - 1] = val

    def __str__(self):
        return "IP(" + ip + ")"


class CIDR(IP):
    def __init__(self, ip: str, mask: int):
        super().__init__(ip)
        if not isinstance(mask, int):
            raise TypeError("Mask value must be an int")
        if mask < 0 or mask > 32:
            raise ValueError("Mask value can only be between 0 and 32")
        self.mask = mask

    def __str__(self):
        return "CIDR(" + str(ip) + "/" + str(mask) + ")"

    @staticmethod
    def parse(ip: str):
        match = cdir_regex.fullmatch(ip)
        if match is None:
            raise ValueError("Input not in CIDR notation")
        return CIDR(match.group(1), int(match.group(2)))


class Node(YamlItemBase):
    class SSH(YamlItemBase):
        def __init__(self, host: str, port: int, username: str, password: str):
            self.host = str(host)
            self.port = port
            self.username = str(username or '') or None
            self.password = str(password or '') or None
            if not isinstance(port, int):
                raise TypeError("Port value must be an int")

        @staticmethod
        def from_dict(dic):
            if not isinstance(dic, dict):
                dic = {}
            if not "host" in dic:
                raise get_dic_error("host", "SSH")
            host = dic["host"]
            port = dic.get("port", 22)
            user = dic.get("username")
            password = dic.get("password")
            return Node.SSH(host, port, user, password)

        def to_url(self):
            res = "" if self.username is None else self.username + "@"
            res += self.host + ":" + str(self.port)
            return res

        def __str__(self):
            return "SSH(" + self.to_url() + ", " + (
                "passwordless" if self.password is None else "*"*len(self.password)) + ")"


    class DNS(YamlItemBase):
        def __init__(self, hosts: list[str], domains: list[str]):
            if (not is_list_of_strings(hosts) and not hosts is None) or (not is_list_of_strings(domains) and not domains is None):
                raise TypeError("DNS hosts and domains must be lists of strings")
            self.hosts = hosts
            self.domains = domains

        @staticmethod
        def from_dict(dic):
            if not isinstance(dic, dict):
                dic = {}
            hosts = dic.get("hosts")
            domains = dic.get("domains")
            return Node.DNS(hosts, domains)

        def __str__(self):
            return "DNS(hosts: " + str(self.hosts) + ", domains: " + str(self.domains) + ")"


    class Network(YamlItemBase):
        def __init__(self, iface: str, addr: CIDR, hostname: str):
            self.iface = str(iface)
            self.ip = addr.ip
            self.mask = addr.mask
            self.hostname = str(hostname)

        def __str__(self):
            return "Network(iface: " + self.iface + ", addr: " + str(self.ip) +\
                "/" + str(self.mask) + ", hostname: " + self.hostname + ")"

        @staticmethod
        def from_dict(dic):
            if not isinstance(dic, dict):
                dic = {}
            if not "iface" in dic:
                raise get_dic_error("iface", "Network")
            if not "hostname" in dic:
                raise get_dic_error("hostname", "Network")
            if not "addr" in dic:
                raise get_dic_error("addr", "Network")
            addr = CIDR.parse(dic["addr"])
            return Node.Network(dic["iface"], addr, dic["hostname"])


    def __init__(self, description: str, ssh: SSH, dns: DNS, provider: Network,
                 management: Network, services: list[str]):
        self.description = str(description or '') or None
        self.ssh = ssh
        self.dns = dns
        self.provider = provider
        self.management = management
        self.services = services

    def __str__(self):
        return "Node(description: " + str(self.description) + ", ssh: " +\
            str(self.ssh) + ", dns: " + str(self.dns) + ", provider: " +\
            str(self.provider) + ", management: " + str(self.management) +\
            ("" if self.services is None else ", services: " + str(self.services)) + ")"

    @staticmethod
    def from_dict(dic):
        if not isinstance(dic, dict):
            dic = {}
        desc = dic.get("description")
        if not "networks" in dic:
            raise get_dic_error("networks", "Node")
        if not "ssh" in dic:
            raise get_dic_error("ssh", "Node")
        ssh = Node.SSH.from_dict(dic["ssh"])
        dns = Node.DNS.from_dict(dic.get("dns"))
        services = dic.get("services")
        # TODO change that so individual nodes can have different settings
        if services is not None and not is_list_of_strings(services):
            raise ValueError("Node's 'services' component must be a list of strings")
        provider = dic["networks"].get("provider")
        management = dic["networks"].get("management")
        if provider is None:
            raise ValueError("The 'provider' network is required on all Nodes")
        if management is None:
            raise ValueError("The 'management' network is required on all Nodes")
        provider = Node.Network.from_dict(provider)
        management = Node.Network.from_dict(management)
        return Node(desc, ssh, dns, provider, management, services)


class ServicesBase(YamlItemBase):
    def __init__(self, name: str, tls: bool):
        if not isinstance(tls, bool):
            raise TypeError("TLS value must be a boolean")
        self.tls = tls
        self.name = str(name)

    def __str__(self):
        return "Service(name: " + self.name + ", tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(dic):
        assoc = {"keystone": Keystone, "cinder": Cinder, "placement": Placement,
                 "glance": Glance, "barbican": Barbican, "heat": Heat,
                 "magnum": Magnum, "neutron": Neutron, "nova": Nova, "zun": Zun,
                 "horizon": Horizon}
        if type(dic) == str:
            dic = {dic: {}}
        elif not isinstance(dic, dict):
            dic = {}
        items = dic.items()
        if len(items) != 1:
            raise ValueError("Invalid value for controller service")
        key, value = list(items)[0]
        if not isinstance(value, dict):
            value = {}
        tls = value.get("tls", False)
        cls = assoc.get(key)
        if cls is None:
            raise ValueError("Unkown openstack controller service: " + key)
        return cls.from_dict(key, tls, value)


class Keystone(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Keystone(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        return Keystone(name, tls)


class Cinder(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Cinder(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Placement(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Placement(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Glance(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Glance(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Barbican(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Barbican(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Heat(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Heat(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Magnum(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Magnum(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Neutron(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Neutron(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Nova(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Nova(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Zun(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Zun(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Horizon(ServicesBase):
    def __init__(self, name: str, tls: bool):
        super().__init__(name, tls)

    def __str__(self):
        return "Horizon(tls: " + str(self.tls) + ")"

    @staticmethod
    def from_dict(name, tls, dic):
        pass


class Property(YamlItemBase):
    def __init__(self, key: str, value: str):
        if key is None or value is None:
            raise ValueError("A property must have a key and a value")
        self.key = str(key)
        self.value = str(value or '') or None

    def __str__(self):
        return "Property(key: " + self.key + ", value: " + self.value + ")"

    @staticmethod
    def from_dict(dic):
        if not isinstance(dic, dict):
            dic = {}
        items = dic.items()
        if len(items) != 1:
            raise ValueError("Property must be a single key:value")
        key, value = list(items)[0]
        return Property(key, value)


class OpenstackConfig(YamlItemBase):
    class Project(YamlItemBase):
        def __init__(self, name:str, description: str, parent: str, domain: str,
                     properties: list[Property], tags: list[str]):
            if name is None:
                raise ValueError("Projects must have a name")
            self.description = str(description or '') or None
            self.parent = str(parent or '') or None
            self.domain = str(domain or '') or None
            self.properties = properties
            self.tags = tags
            self.name = str(name)

        def __str__(self):
            return "Project(name: " + self.name + ", description: " +\
                str(self.description) + ", parent: " + str(self.parent) +\
                ", domain: " + str(self.domain) + ", properties: " +\
                str(self.properties) + ", tags: " + str(self.tags) + ")"

        @staticmethod
        def from_dict(dic):
            if not isinstance(dic, dict):
                dic = {}
            items = dic.items()
            if len(items) != 1:
                raise ValueError("Invalid value for project")
            key, value = list(items)[0]
            if not isinstance(value, dict):
                value = {}
            description = value.get("description")
            parent = value.get("parent")
            domain = value.get("domain", "default")
            properties = value.get("properties", [])
            tags = value.get("tags", [])
            return OpenstackConfig.Project(key, description, parent, domain, properties, tags)


    class Role(YamlItemBase):
        def __init__(self, name: str, description: str, domain: str):
            if name is None:
                raise ValueError("Projects must have a name")
            self.description = str(description or '') or None
            self.domain = str(domain or '') or None
            self.name = str(name)

        def __str__(self):
            return "Role(name: " + self.name + ", description: " + str(self.description) + ", domain: " +\
                str(self.domain) + ")"

        @staticmethod
        def from_dict(dic):
            if not isinstance(dic, dict):
                dic = {}
            items = dic.items()
            if len(items) != 1:
                raise ValueError("Invalid value for role")
            key, value = list(items)[0]
            if not isinstance(value, dict):
                value = {}
            description = value.get("description")
            domain = value.get("domain", "default")
            return OpenstackConfig.Role(key, description, domain)


    class User(YamlItemBase):
        def __init__(self, username: str, password: str, email: str,
                     description: str, domain: str, project: str):
            if password is None:
                raise ValueError("Users must have a password")
            if username is None:
                raise ValueError("Users must have a name")
            self.description = str(description or '') or None
            self.domain = str(domain or '') or None
            self.project = str(project or '') or None
            self.password = str(password)
            self.email = str(email or '') or None
            self.username = str(username)

        def __str__(self):
            return "User(name: " + self.username + ", description: " +\
                str(self.description) + ", domain: " + str(self.domain) +\
                ", project: " + str(self.project) + ", email: " + str(self.email) + ")"

        @staticmethod
        def from_dict(dic):
            if not isinstance(dic, dict):
                dic = {}
            items = dic.items()
            if len(items) != 1:
                raise ValueError("Invalid value for user")
            key, value = list(items)[0]
            if not isinstance(value, dict):
                value = {}
            description = value.get("description")
            domain = value.get("domain")
            project = value.get("project")
            password = value.get("password")
            email = value.get("email")
            return OpenstackConfig.User(key, password, email, description, domain, project)


    def __init__(self, projects: list[Project], roles: list[Role], users: list[User]):
        self.projects = projects
        self.roles = roles
        self.users = users

    def __str__(self):
        return "OpenstackConfig(projects: " + str(self.projects) + ", roles: " +\
            str(self.roles) + ", users: " + str(self.users) + ")"

    @staticmethod
    def from_dict(dic):
        if not isinstance(dic, dict):
            dic = {}
        projects = []
        roles = []
        users = []
        for item in dic.get("projects"):
            projects.append(OpenstackConfig.Project.from_dict(item))
        for item in dic.get("roles"):
            roles.append(OpenstackConfig.Role.from_dict(item))
        for item in dic.get("users"):
            users.append(OpenstackConfig.User.from_dict(item))
        return OpenstackConfig(projects, roles, users)

class Config(YamlItemBase):
    def __init__(self, controller_nodes: list[Node], worker_nodes: list[Node],
                 controller_services: list[ServicesBase], openstack_config: OpenstackConfig):
        self.controller_nodes = controller_nodes
        self.worker_nodes = worker_nodes
        self.controller_services = controller_services
        self.openstack_config = openstack_config

    def __str__(self):
        return "Config(controller_nodes: " + str(self.controller_nodes) +\
            ", worker_nodes: " + str(self.worker_nodes) +\
            ", controller_services: " + str(self.controller_services) +\
            ", openstack_config: " + str(self.openstack_config) + ")"

    @staticmethod
    def from_dict(dic):
        if not isinstance(dic, dict):
            dic = {}
        worker_nodes = []
        controller_nodes = []
        controller_services = []
        openstack_config = OpenstackConfig.from_dict(dic.get("openstack_config"))

        for item in dic.get("controller_nodes", []):
            controller_nodes.append(Node.from_dict(item))
        for item in dic.get("worker_nodes", []):
            worker_nodes.append(Node.from_dict(item))
        for item in dic.get("controller_services", []):
            controller_services.append(ServicesBase.from_dict(item))
        return Config(controller_nodes, worker_nodes, controller_services, openstack_config)


def usage(only_usage=False):
    out=sys.stderr if not only_usage else sys.stdout
    print("Usage : " + sys.argv[0] + " config_file.yaml [config_file2.yaml... ]", file=out)
    print("", file=out)
    if only_usage: # TODO better wording
        print("Parse one (or more) config files and output an easier format for bash scripts.")
        print("\nIf multiples files are given, they will be merged in order of appearence.")
        print("Overlaping keys will be replaced by the last file mentioning them.")
        return
    if len(sys.argv) == 1:
        print("No config file given. Please give at least one config file to parse.", file=out)


def resolve_env_value(val, default=None):
    match = env_var_regex.search(val)
    if match:
        idx = match.span(0)
        prev = val[:idx[0]]
        nex = val[idx[1]:]
        nb_bslash = 0
        for c in prev[::-1]:
            if c != '\\':
                break;
            nb_bslash = nb_bslash + 1
        prev = prev[:len(prev)-nb_bslash] + '\\'*int(nb_bslash/2)
        if nb_bslash % 2 == 1:
            print(nb_bslash)
            return prev + match.group(0) + resolve_env_value(nex, nex)
        match = match.group(1) or match.group(2)
        if match in os.environ:
            return prev + os.environ[match] + resolve_env_value(nex, nex)
        raise ValueError("Missing env variable: $" + match)
    return default


def resolve_env_list(lst):
    for i, item in enumerate(lst):
        if type(item) == list:
            lst[i] = resolve_env_list(item)
        elif type(item) == dict:
            lst[i] = resolve_env_dic(item)
        elif type(item) == str:
            val = resolve_env_value(item)
            if val is not None:
                lst[i] = val
    return lst


def resolve_env_dic(dic):
    resolve_keys = []
    for key, value in dic.items():
        if type(key) == str:
            val = resolve_env_value(key)
            if val is not None:
                resolve_keys.append((key, val))
        if type(value) == dict:
            dic[key] = resolve_env_dic(value)
        elif type(value) == list:
            dic[key] = resolve_env_list(value)
        elif type(value) == str:
            dic[key] = resolve_env_value(value, value)
    for old, new in resolve_keys:
        dic[new] = dic.pop(old)
    return dic


def main():
    if len(sys.argv) < 2:
        usage()
        return 1
    if sys.argv[1] == "-h" or sys.argv[1] == "--help":
        usage(True)
        return 0
    data = None
    try:
        for config in sys.argv[1:]:
            with open(config) as f:
                if data is None:
                    data = yaml.safe_load(f)
                else:
                    # TODO Do we want to merge sub-dictonary as well ?
                    data.update(yaml.safe_load(f))
        data = resolve_env_dic(data)
        config = Config.from_dict(data)
        # TODO Validate config
        # TODO Output config
        print(config)
        return 0
    except OSError as e:
        print("Fatal Error: '" + e.filename + "': " + e.strerror)
    except yaml.scanner.ScannerError as e:
        mark = e.problem_mark
        print("Fatal Error: '" + mark.name + "': " + e.problem +
              " (line: " + str(mark.line) + ", column: " + str(mark.column) + ")")
    return 1

if __name__ == "__main__":
    exit(main())
