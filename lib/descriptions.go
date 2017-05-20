package sault

const (
	descriptionGlobal = `
==================================================
{{ " sault" | cyan }}: The authentication proxy for SSH servers
==================================================

"sault" acts like the reverse proxy, so the native openssh client and server work transparently.

To deploy the sault in your system, follow these steps.
1. In the server side, download and install sault.
  Get the latest pre-built binary at https://github.com/spikeekips/sault/releases , and extract it in $PATH.
2. Create sault default directory, like {{ "~/.sault" | yellow }}.
  {{ "$ mkdir ~./sault" | magenta }}
3. Initialize sault environment.
  {{ "$ cd ~./sault" | magenta }}
  {{ "$ sault init admin ~/.ssh/admin.pub" | magenta }}
4. Run sault server.
  {{ "$ cd ~./sault" | magenta }}
  {{ "$ sault server run" | magenta }}
5. Add users and ssh hosts like this.
  {{ "$ sault user add spikeekips ~/.ssh/id_rsa.pub" | magenta }}
  The "spikeekips" is the name for sault, it is not ssh user account name.
  {{ "$ sault host add president-server ubuntu@192.168.99.110:22" | magenta }}
  You added the, "president-server", it will be used host name to connect to "ubuntu@192.168.99.110:22".
  {{ "$ sault user link spikeekips president-server" | magenta }}
  This will allow to access "spikeekips" to "president-server" with the "ubuntu" user account.
6. Connect with your ssh client to ssh server
  {{ "$ ssh spikeekips ubuntu@president-server" | magenta }}

For more information, check out the helps with {{ "$ sault <command> -h" | magenta }}, or visit https://github.com/spikeekips/sault .
{{ line " -" }}
sault runs as server and client. The flags in the belows help to run server and client.

{{ "-logLevel" | yellow }}:
  With {{ "-logLevel" | yellow }}, 'debug', 'info', 'error', 'warn', and 'fatal' can be set like other programs, and interesting thing is 'quiet', it will mute all the logs.

{{ "-at" | yellow }}:
 sault can be run as server and it's client. In client, you can set the sault server to connect with {{ "-at" | yellow }}. It's value has the same format of ssh connection address,
  {{ "<sault server name>" | yellow }}@{{ "<sault server address or ip>" | yellow }}:{{ "<sault server port>" | yellow }}
  The {{ "<sault server name>" | yellow }} is the special account to connect sault control session, it can be set your own name in sault configuration,
    {{ "[server]" | green }}
    {{ "server_name: \"son\"" | green }}

{{ "-identity" | yellow }}:
  Set the ssh private key file to identify for authentication,
    {{ "$ sault -identity ~/.ssh/id_rsa whoami" | magenta }}
  Without {{ "-identity" | yellow }}, sault will use {{ "ssh-agent" | yellow }}. If new private key, sault will ask passpharas for encrypted private key file, almost same like native ssh client.
{{ line " -" }}
`

	descriptionHostActive = `
With {{ "host active" | yellow }} command, you can activate the host or vice versa.

As you expected, the deactivated host will be not allowed to access. {{ "host remove" | yellow }} will deactivate and also remove host data, but the the deactivated host will keep it's data, so the *deactivating* host will be safer way to manage hosts.

Appending '{{ "-" | yellow }}' to the end of hostName, makes the host to be deactivated.

Activating 'server0'
 {{ "$ sault host active server0" | magenta }}

Deactivating 'server0'
 {{ "$ sault host active server0-" | magenta }}
	`

	descriptionHostAdd = `
'{{ "host add" | yellow }}' adds the host to sault and with the '{{ "user link" | yellow }}', the end user can access to the host. For example, you can add the host, '{{ "ubuntu@192.168.99.110:22" | yellow }}' with the host name, '{{ "president-server" | yellow }}',
  {{ "$ sault host add president-server ubuntu@192.168.99.110:22" | magenta }}
    Then, this host can be linked to the user, "spikeekips" like this,
  {{ "$ sault user link spikeekips president-server" | magenta }}
    Everything is done, the real ssh server, '{{ "ubuntu@192.168.99.110:22" | yellow }}' can be accessed like this,
  {{ "$ ssh -p 2222 president-server@sault-server" | magenta }}
    The '{{ "<hostName>" | yellow }}' will be used as an account name.

The {{ "address" | yellow }} and {{ "port" | yellow }} can be accessed from sault server, not from the end user.

Like '{{ "$ ssh -p 2222 president-server@sault-server" | magenta }}', if the '{{ "<hostName>" | yellow }}' is used as an account name, how the real user account can be determined? By default, the '{{ "<defaultAccount>" | yellow }}' will be used. The other real account can be set,
  {{ "$ ssh -p 2222" | magenta }} {{ "other-account+" | cyan }}{{ "president-server@sault-server" | magenta }}
    The '{{ "other-account+" | cyan }}' is the real user account in ssh server and can be set, concatenating '{{ "<hostName>" | yellow }}' with "+". The real user accounts to be accessed can be limited by '{{ "-accounts+" | yellow }}' flag.

As you already know, sault is the proxy of ssh authentication process, when you try to connect the real ssh server, your ssh identity will not be used to authenticate in the real ssh server. Instead of your own identity, sault use it's own private key to connect to the real ssh server. Your own identity only will be used to authenticate in the sault, not the real server. Naturally the public key of your identity must be appended in '~/.ssh/authorized_keys' of your account of ssh server, if not, '{{ "host add" | yellow }}' tries to register the sault public key to the target ssh server. If injecting sault public key to the host is failed, the host will not be added :), but with '{{ "-force" | yellow }}' flag will add by force.
`

	descriptionHostAlive = `
{{ "host alive" | yellow }} checks the connectivity of ssh server from sault server. If you omit the {{ "<hostName>" | yellow }}, all the available hosts will be checked.
	`

	descriptionHostGet = `
{{ "host get" | yellow }} will show the hosts information. If you omit the {{ "<hostName>" | yellow }}, all the available hosts will be printed. You can filter the result by {{ "-filter" | yellow }} flag, {{ "-filter active" | yellow }} shows the activated hosts and {{ "-filter deactivated" | yellow }} will show the deactivated hosts.
	`

	descriptionHostRemove = `
{{ "host remove" | yellow }} will remove the host data from sault server permanately. You can set the multiple '{{ "<hostName>" | yellow }}'s,
  {{ "$ sault host remove president-server minister-server" | magenta }}
	`

	descriptionHostUpdate = `
{{ "host update" | yellow }} will update host data. For example,
  {{ "$ sault host update president-server hostName ex-president-server" | magenta }}
  This will update the host name of 'president-server' to 'ex-president-server'

You can change these data, the value is corresponded with the value of {{ "host add" | yellow }}.
* {{ "hostName" | yellow }}: host name
* {{ "defaultAccount" | yellow }}: default account
* {{ "accuonts" | yellow }}: accounts to be allowed to access
* {{ "address" | yellow }}: server name or ip address without port
* {{ "port" | yellow }}: port number of host
	`

	descriptionInit = `
Initialize sault environment.

At first, create new directory for sault configuration, and change directory to it, and then simply just run,
{{ "$ mkdir -p ~/.sault" | magenta }}
{{ "$ cd ~/.sault" | magenta }}
{{ "$ sault init spikeekips ~/.ssh/id_rsa.pub" | magenta }}

By default current directory will be used.

This will create the sault configuration files in current directory, the configuration file, {{ "sault.conf" | yellow }}, registry file, {{ "registry.toml" | yellow }} and ssh related key files. You can also set the different directory with '{{ "-configDir <directory>" | yellow }}',
{{ "$ sault init -configDir ~/.another-sault spikeekips ~/.ssh/another-id_rsa.pub" | magenta }}
`
	descriptionUserActive = `
With {{ "user active" | yellow }} command, you can activate the user or vice versa.

As you expected, the deactivated user will be not allowed to access. {{ "user remove" | yellow }} will deactivate and also remove user data, but the the deactivated user will keep it's data, so the *deactivating* user will be safer way to manage users.

Appending '{{ "-" | yellow }}' to the end of userName, makes the user to be deactivated.

Activating user, "spikeekips"
 {{ "$ sault user active spikeekips" | magenta }}

Deactivating "spikeekips"
 {{ "$ sault user active spikeekips-" | magenta }}
	`
	descriptionUserAdd = `
You can add user by the {{ "user add" | yellow }} with the {{ "<userName>" | yellow }} and {{ "<publicKeyFile>" | yellow }}, this user is the user for sault, not your own ssh server.

In sault, there are 2 types of user,
* sault user
* (user) account

{{ "sault user" | yellow }}:
  is managed by sault and contains the authentication information like ssh public key and unique name. The user name of this is not used to connect to your real ssh host.
{{ "account" | yellow }}:
  means the ssh user account. Internally in sault {{ "sault user" | yellow }} is linked with the multiple {{ "account" | yellow }}s of host and hosts.

{{ "<publicKeyFile>" | yellow }} must be set by file path, not the content of public key.
	`

	descriptionUserAdmin = `
With {{ "user admin" | yellow }} command, you can make the user to be admin or vice versa.

Appending '{{ "-" | yellow }}' to the end of userName, makes the user not to be admin.

Making 'spikeekips' to be admin 
 {{ "$ sault user admin spikeekips" | magenta }}

Making 'spikeekips' not to be admin 
 {{ "$ sault user admin spikeekips-" | magenta }}

Like {{ "user remove" | yellow }}, you can set the multiple userName.
	`

	descriptionUserGet = `
{{ "user get" | yellow }} will show you the users information. If you omit the {{ "<userName>" | yellow }}, all the available users will be printed. You can filter the result by {{ "-filter" | yellow }} flag, {{ "-filter active" | yellow }} shows you the activated users and {{ "-filter deactivated" | yellow }} will show you the deactivated users.
You can also find user information by it's public key by {{ "-publicKey" | yellow }} flag. The value of {{ "-publicKey" | yellow }} can be set like this,
  {{ "$ sault user get -publicKey \"ssh-rsa AAAAB...31eYGw== spikeekips@gmail.com\"" | magenta }}
  This will show you the user information, which has the public key.
	`

	descriptionUserLink = `
With {{ "user link" | yellow }} can link the sault user with the specific host,
  {{ "$ sault user link spikeekips president-server" | yellow }}
  This will link the user, 'spikeekips' with the host, 'president-server'.

Linking without specifying {{ "<account>" | yellow }}, allows to access all the avaiable accounts of that host, the available accounts can be limited by "{{ "accounts" | yellow }}" of host data.

To unlink the user with the host, append {{ "-" | yellow }} at the end of host name,
  {{ "$ sault user link spikeekips president-server-" | yellow }}
  This will prevent the user, 'spikeekips' to access to the host, 'president-server' with any kind of account.
	`

	descriptionUserRemove = `
{{ "user remove" | yellow }} will remove the user data from sault server permanately. You can set the multiple '{{ "<userName>" | yellow }}'s,
  {{ "$ sault user remove spikeekips casobon" | magenta }}
	`

	descriptionUserUpdate = `
{{ "user update" | yellow }} will update user data. For example,
  {{ "$ sault user update spikeekips userName ekips" | magenta }}
  This will update the user name of 'spikeekips' to 'ekips'.

	`

	descriptionWhoAmI = `
{{ "whoami" | yellow }} command prints the current sault user information.

The interesting thing is, you can use {{ "whoami" | yellow }} command with the naitive ssh client,
  {{ "$ ssh -p 2222 sault@sault-server whoami" | yellow }}
  For more details, see the main help message by {{ "$ sault -h" | yellow }}.
	`

	descriptionServerRun = `
{{ "server run" | yellow }} will run the sault server.

By default, the port will be '{{ "2222" | yellow }}' and {{ "-loglLevel" | yellow }} is '{{ "quiet" | yellow }}'

Usually sault is run at the sault environment directory, but your can set the other environment directory by {{ "-configDir" | yellow }}.
	`

	descriptionServerConfig = `
{{ "server config" | yellow }} shows the current configuration of sault server.
	`

	descriptionServerKeys = `
{{ "server clientKeys" | yellow }} shows the private key and public key for using to connect the hosts.
	`
)
