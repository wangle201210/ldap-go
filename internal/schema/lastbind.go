package schema

import "fmt"

var openLDAPLastBindAttributeTypes = []string{
	"( 1.3.6.1.4.1.4203.1.12.2.3.5.2 NAME 'olcLastBindForwardUpdates' DESC 'Allow authTimestamp updates to be forwarded via updateref' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
}

var openLDAPLastBindObjectClasses = []string{
	"( 1.3.6.1.4.1.4203.1.12.2.4.4.5.1 NAME 'olcLastBindConfig' DESC 'Last Bind configuration' SUP olcOverlayConfig MAY olcLastBindForwardUpdates )",
}

func RegisterOpenLDAPLastBindSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP lastbind schema: nil registry")
	}
	for _, description := range openLDAPLastBindAttributeTypes {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			return err
		}
	}
	for _, description := range openLDAPLastBindObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			return err
		}
	}
	return nil
}
