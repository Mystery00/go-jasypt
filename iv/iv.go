package iv

type Generator interface {
	GenerateIv(lengthBytes int) ([]byte, error)

	IncludePlainIvInEncryptionResults() bool
}
