// +build persephone_blacklist

package runtime

const (
	Persephone = "persephone"
)

func init() {
	Homeserver = Persephone
}
