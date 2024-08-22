package ipsetcmd

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type IPSet struct {
	binaryPath string
	setName    string
}

type CreateOptions struct {
	Timeout string
	MaxElem string
	Family  string
	Type    string
}

const ipsetBinary = "ipset"

func NewIPSet(setName string) (*IPSet, error) {
	ipsetBin, err := exec.LookPath(ipsetBinary)
	if err != nil {
		return nil, errors.New("unable to find ipset")
	}
	return &IPSet{
		binaryPath: ipsetBin,
		setName:    setName,
	}, nil
}

//Wraps all the ipset commands

func (i *IPSet) Create(opts CreateOptions) error {
	cmdArgs := []string{"create", i.setName}

	if opts.Type != "" {
		cmdArgs = append(cmdArgs, opts.Type)
	}

	if opts.Timeout != "" {
		cmdArgs = append(cmdArgs, "timeout", opts.Timeout)
	}

	if opts.MaxElem != "" {
		cmdArgs = append(cmdArgs, "maxelem", opts.MaxElem)
	}

	if opts.Family != "" {
		cmdArgs = append(cmdArgs, "family", opts.Family)
	}

	cmd := exec.Command(i.binaryPath, cmdArgs...)

	log.Debugf("ipset create command: %v", cmd.String())

	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error creating ipset: %s", out)
	}

	return nil
}

func (i *IPSet) Delete() error {
	cmd := exec.Command(i.binaryPath, "destroy", i.setName)

	log.Debugf("ipset delete command: %v", cmd.String())

	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error creating ipset: %s", out)
	}

	return nil
}

func (i *IPSet) Add(entry string) error {
	cmd := exec.Command(i.binaryPath, "add", i.setName, entry)

	log.Debugf("ipset add command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error creating ipset: %s", out)
	}

	return nil
}

func (i *IPSet) DeleteEntry(entry string) error {
	cmd := exec.Command(i.binaryPath, "del", i.setName, entry)

	log.Debugf("ipset delete entry command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error creating ipset: %s", out)
	}

	return nil
}

func (i *IPSet) List() ([]string, error) {
	cmd := exec.Command(i.binaryPath, "list", i.setName)

	log.Debugf("ipset list command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("error listing ipset: %s", out)
	}

	return strings.Split(string(out), "\n"), nil
}

func (i *IPSet) Flush() error {
	cmd := exec.Command(i.binaryPath, "flush", i.setName)

	log.Debugf("ipset flush command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error flushing ipset: %s", out)
	}

	return nil
}

func (i *IPSet) Destroy() error {
	cmd := exec.Command(i.binaryPath, "destroy", i.setName)

	log.Debugf("ipset destroy command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error destroying ipset: %s", out)
	}

	return nil
}

func (i *IPSet) Rename(toSetName string) error {
	cmd := exec.Command(i.binaryPath, "rename", i.setName, toSetName)

	log.Debugf("ipset rename command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error renaming ipset: %s", out)
	}

	i.setName = toSetName

	return nil
}

func (i *IPSet) Test(entry string) error {
	cmd := exec.Command(i.binaryPath, "test", i.setName, entry)

	log.Debugf("ipset test command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error testing ipset: %s", out)
	}

	return nil
}

func (i *IPSet) Save() ([]string, error) {
	cmd := exec.Command(i.binaryPath, "save", i.setName)

	log.Debugf("ipset save command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("error saving ipset: %s", out)
	}
	return strings.Split(string(out), "\n"), nil
}

func (i *IPSet) Restore(filename string) error {
	cmd := exec.Command(i.binaryPath, "restore", "-file", filename)

	log.Debugf("ipset restore command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error restoring ipset: %s", out)
	}

	return nil
}

func (i *IPSet) Swap(toSetName string) error {
	cmd := exec.Command(i.binaryPath, "swap", i.setName, toSetName)

	log.Debugf("ipset swap command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("error swapping ipset: %s", out)
	}

	i.setName = toSetName

	return nil
}

func (i *IPSet) Name() string {
	return i.setName
}

func (i *IPSet) Exists() bool {
	cmd := exec.Command(i.binaryPath, "list", i.setName)

	err := cmd.Run()

	return err == nil
}

func (i *IPSet) Len() int {
	cmd := exec.Command(i.binaryPath, "list", i.setName)

	log.Debugf("ipset list command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return 0
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), "number of entries:") {
			fields := strings.Split(line, ":")
			if len(fields) != 2 {
				continue
			}
			count, err := strconv.Atoi(strings.TrimSpace(fields[1]))
			if err != nil {
				return 0
			}
			return count
		}
	}

	return 0
}

//Helpers

func GetSetsStartingWith(name string) (map[string]*IPSet, error) {
	cmd := exec.Command(ipsetBinary, "list", "-name")

	log.Debugf("ipset list command: %v", cmd.String())
	out, err := cmd.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("error listing ipset: %s", out)
	}

	sets := make(map[string]*IPSet, 0)

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, name) {
			fields := strings.Fields(line)
			if len(fields) != 1 {
				continue
			}
			set, err := NewIPSet(fields[0])
			if err != nil {
				return nil, err
			}
			sets[fields[0]] = set
		}
	}

	return sets, nil
}
