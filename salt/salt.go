package salt

type Generator interface {
	GenerateSalt(lengthBytes int) ([]byte, error)

	IncludePlainSaltInEncryptionResults() bool
}
