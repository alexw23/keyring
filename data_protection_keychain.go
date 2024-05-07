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

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
}

func init() {
	supportedBackends[DataProtectionKeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		var authCtxOptions gokeychain.AuthenticationContextOptions
		var authCtx *gokeychain.AuthenticationContext

		if cfg.BioMetricsAllowableReuseDuration > 0 {
			authCtxOptions.AllowableReuseDuration = cfg.BioMetricsAllowableReuseDuration
		}

		authCtx = gokeychain.CreateAuthenticationContext(authCtxOptions)

		kc := &DataProtectionKeychain{
			service: cfg.ServiceName,

			// Set the isAccessibleWhenUnlocked to the boolean value of
			// KeychainAccessibleWhenUnlocked is a shorthand for setting the accessibility value.
			// See: https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked
			isAccessibleWhenUnlocked: cfg.KeychainAccessibleWhenUnlocked,

			authenticationContext: authCtx,
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
	query.SetAuthenticationContext(k.authenticationContext)

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
	query.SetAuthenticationContext(k.authenticationContext)

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
	queryItem.SetAuthenticationContext(k.authenticationContext)

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

	if k.isSynchronizable && !item.KeychainNotSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	flags := gokeychain.AccessControlFlagsBiometryCurrentSet
	kcItem.SetAccessControl(gokeychain.AccessControlFlags(flags))

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

	debugf("Removing keychain item service=%q, account=%q", k.service, key)
	err := gokeychain.DeleteItem(item)
	if err == gokeychain.ErrorItemNotFound {
		return ErrKeyNotFound
	}

	return err
}

func (k *DataProtectionKeychain) Keys() ([]string, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)
	query.SetAuthenticationContext(k.authenticationContext)

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
