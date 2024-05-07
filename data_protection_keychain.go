//go:build darwin && cgo
// +build darwin,cgo

package keyring

import (
	"errors"
	"fmt"

	gokeychain "github.com/keybase/go-keychain"
)

type DataProtectionKeychain struct {
	service string

	authenticationContext *gokeychain.AuthenticationContext

	isSynchronizable   bool
	accessControlFlags gokeychain.AccessControlFlags
	accessConstraint   gokeychain.Accessible
}

func init() {
	supportedBackends[DataProtectionKeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		if !gokeychain.CanUseDataProtectionKeychain() {
			return nil, errors.New("SecAccessControl is not available on this platform")
		}

		var authCtxOptions gokeychain.AuthenticationContextOptions

		if cfg.BioMetricsAllowableReuseDuration > 0 {
			authCtxOptions.AllowableReuseDuration = cfg.BioMetricsAllowableReuseDuration
		} else if cfg.BioMetricsAllowableReuseDuration < 0 {
			return nil, errors.New("BioMetricsAllowableReuseDuration must be greater than 0")
		}

		authCtx := gokeychain.CreateAuthenticationContext(authCtxOptions)

		accessConstraint, err := mapConstraint(cfg.KeychainAccessConstraint)
		if err != nil {
			return nil, err
		}

		accessControlFlags, err := mapStringsToFlags(cfg.KeychainAccessControl)
		if err != nil {
			return nil, err
		}

		kc := &DataProtectionKeychain{
			service: cfg.ServiceName,

			authenticationContext: authCtx,
			accessControlFlags:    accessControlFlags,
			accessConstraint:      accessConstraint,
		}

		if kc.accessConstraint == 0 {
			kc.accessConstraint = gokeychain.AccessibleWhenUnlockedThisDeviceOnly
		}

		return kc, nil
	})
}

func (k *DataProtectionKeychain) Get(key string) (Item, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	query.SetUseDataProtectionKeychain(true)

	err := query.SetAuthenticationContext(k.authenticationContext)
	if err != nil {
		return Item{}, err
	}

	debugf("Querying item in data protection keychain for service=%q, account=%q", k.service, key)
	results, err := gokeychain.QueryItem(query)

	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	debugf("Found item %q", results[0].Label)
	return item, nil
}

func (k *DataProtectionKeychain) GetMetadata(key string) (Metadata, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(false)
	query.SetReturnRef(true)
	query.SetUseDataProtectionKeychain(true)

	err := query.SetAuthenticationContext(k.authenticationContext)
	if err != nil {
		return Metadata{}, err
	}

	debugf("Querying keychain for metadata of service=%q, account=%q", k.service, key)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	} else if err != nil {
		debugf("Error: %#v", err)
		return Metadata{}, err
	}

	md := Metadata{
		Item: &Item{
			Key:         key,
			Label:       results[0].Label,
			Description: results[0].Description,
		},
		ModificationTime: results[0].ModificationDate,
	}

	debugf("Found metadata for %q", md.Item.Label)

	return md, nil
}

func (k *DataProtectionKeychain) updateItem(account string, data []byte) error {
	queryItem := gokeychain.NewItem()
	queryItem.SetSecClass(gokeychain.SecClassGenericPassword)
	queryItem.SetService(k.service)
	queryItem.SetAccount(account)
	queryItem.SetMatchLimit(gokeychain.MatchLimitOne)
	queryItem.SetReturnAttributes(true)
	queryItem.SetUseDataProtectionKeychain(true)

	err := queryItem.SetAuthenticationContext(k.authenticationContext)
	if err != nil {
		return err
	}

	results, err := gokeychain.QueryItem(queryItem)
	if err != nil {
		return fmt.Errorf("failed to query keychain: %v", err)
	}
	if len(results) == 0 {
		return errors.New("no results")
	}

	updateItem := gokeychain.NewItem()
	updateItem.SetData(data)

	if err := gokeychain.UpdateItem(queryItem, updateItem); err != nil {
		return fmt.Errorf("failed to update item in data protection keychain: %v", err)
	}

	return nil
}

func (k *DataProtectionKeychain) Set(item Item) error {
	kcItem := gokeychain.NewItem()
	kcItem.SetSecClass(gokeychain.SecClassGenericPassword)
	kcItem.SetService(k.service)
	kcItem.SetAccount(item.Key)
	kcItem.SetLabel(item.Label)
	kcItem.SetDescription(item.Description)
	kcItem.SetData(item.Data)
	kcItem.SetUseDataProtectionKeychain(true)

	if k.isSynchronizable && !item.KeychainNotSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	kcItem.SetAccessControl(k.accessControlFlags, k.accessConstraint)

	debugf("Adding service=%q, label=%q, account=%q", k.service, item.Label, item.Key)

	err := gokeychain.AddItem(kcItem)

	if err == gokeychain.ErrorDuplicateItem {
		debugf("Item already exists, updating item service=%q, account=%q", k.service, item.Key)
		err = k.updateItem(item.Key, item.Data)
	}

	if err != nil {
		return err
	}

	return nil
}

func (k *DataProtectionKeychain) Remove(key string) error {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.service)
	item.SetAccount(key)
	item.SetUseDataProtectionKeychain(true)

	debugf("Removing keychain item service=%q, account=%q", k.service, key)
	err := gokeychain.DeleteItem(item)
	if err == gokeychain.ErrorItemNotFound {
		return ErrKeyNotFound
	}

	if err != nil {
		return fmt.Errorf("failed to delete item from data protection keychain: %v", err)
	}

	return nil
}

func (k *DataProtectionKeychain) Keys() ([]string, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)
	query.SetUseDataProtectionKeychain(true)

	err := query.SetAuthenticationContext(k.authenticationContext)
	if err != nil {
		return nil, err
	}

	debugf("Querying keys in data protection keychain for service=%q", k.service)
	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	debugf("Found %d results", len(results))

	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}

func mapStringsToFlags(strings []string) (gokeychain.AccessControlFlags, error) {
	var flags gokeychain.AccessControlFlags

	flagMap := map[string]gokeychain.AccessControlFlags{
		"UserPresence":        gokeychain.AccessControlFlagsUserPresence,
		"BiometryAny":         gokeychain.AccessControlFlagsBiometryAny,
		"BiometryCurrentSet":  gokeychain.AccessControlFlagsBiometryCurrentSet,
		"DevicePasscode":      gokeychain.AccessControlFlagsDevicePasscode,
		"Watch":               gokeychain.AccessControlFlagsWatch,
		"Or":                  gokeychain.AccessControlFlagsOr,
		"And":                 gokeychain.AccessControlFlagsAnd,
		"PrivateKeyUsage":     gokeychain.AccessControlFlagsPrivateKeyUsage,
		"ApplicationPassword": gokeychain.AccessControlFlagsApplicationPassword,
	}

	for _, flagString := range strings {
		if flag, exists := flagMap[flagString]; exists {
			flags |= flag // Combine flags using bitwise OR
		} else {
			return 0, fmt.Errorf("invalid access control flag: %s", flagString)
		}
	}

	return flags, nil
}

func mapConstraint(constraint string) (gokeychain.Accessible, error) {
	switch constraint {
	case "AccessibleWhenUnlocked":
		return gokeychain.AccessibleWhenUnlocked, nil
	case "AccessibleAfterFirstUnlock":
		return gokeychain.AccessibleAfterFirstUnlock, nil
	case "AccessibleAfterFirstUnlockThisDeviceOnly":
		return gokeychain.AccessibleAfterFirstUnlockThisDeviceOnly, nil
	case "AccessibleWhenPasscodeSetThisDeviceOnly":
		return gokeychain.AccessibleWhenPasscodeSetThisDeviceOnly, nil
	case "AccessibleWhenUnlockedThisDeviceOnly":
		return gokeychain.AccessibleWhenUnlockedThisDeviceOnly, nil
	// @deprecated
	// https://developer.apple.com/documentation/security/ksecattraccessiblealwaysthisdeviceonly
	// https://developer.apple.com/documentation/security/ksecattraccessiblealways
	case "AccessibleAccessibleAlwaysThisDeviceOnly":
	case "AccessibleAlways":
		return 0, fmt.Errorf("AccessibleAlways and AccessibleAccessibleAlwaysThisDeviceOnly have been deprecated, use AccessibleWhenUnlockedThisDeviceOnly instead")
	case "":
		return gokeychain.AccessibleDefault, nil
	default:
		return 0, fmt.Errorf("invalid access constraint: %s", constraint)
	}

	return 0, nil
}
