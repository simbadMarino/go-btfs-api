package shell

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	utils "github.com/TRON-US/go-btfs-api/utils"
	"github.com/gogo/protobuf/proto"
	"github.com/tron-us/go-common/v2/json"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/tron-us/go-btfs-common/crypto"
	escrowpb "github.com/tron-us/go-btfs-common/protos/escrow"
	guardpb "github.com/tron-us/go-btfs-common/protos/guard"
	ledgerpb "github.com/tron-us/go-btfs-common/protos/ledger"
	cutils "github.com/tron-us/go-btfs-common/utils"
)

type StorageUploadOpts = func(*RequestBuilder) error

type storageUploadResponse struct {
	ID string
}

type Shard struct {
	ContractId string
	Price      int64
	Host       string
	Status     string
}

type Storage struct {
	Status   string
	Message  string
	FileHash string
	Shards   map[string]Shard
}

type ContractItem struct {
	Key      string `json:"key"`
	Contract string `json:"contract"`
}

type Contracts struct {
	Contracts []ContractItem `json:contracts`
}

type UnsignedData struct {
	Unsigned string
	Opcode   string
	Price    int64
}

type StorageOpts = func(*RequestBuilder) error

func UploadMode(mode string) StorageOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("m", mode)
		return nil
	}
}

func Hosts(hosts string) StorageOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("s", hosts)
		return nil
	}
}

func (d UnsignedData) SignData(privateKey string) ([]byte, error) {
	privKey, err := crypto.ToPrivKey(privateKey)
	if err != nil {
		return nil, err
	}
	signedData, err := privKey.Sign([]byte(d.Unsigned))
	if err != nil {
		return nil, err
	}
	return signedData, nil
}

func (d UnsignedData) SignBalanceData(privateKey string) (*ledgerpb.SignedPublicKey, error) {
	privKey, err := crypto.ToPrivKey(privateKey)
	if err != nil {
		return nil, err
	}
	pubKeyRaw, err := ic.MarshalPublicKey(privKey.GetPublic())
	if err != nil {
		return nil, err
	}
	lgPubKey := &ledgerpb.PublicKey{
		Key: pubKeyRaw,
	}
	sig, err := crypto.Sign(privKey, lgPubKey)
	if err != nil {
		return nil, err
	}
	lgSignedPubKey := &ledgerpb.SignedPublicKey{
		Key:       lgPubKey,
		Signature: sig,
	}
	return lgSignedPubKey, nil
}

func (c Contracts) SignContracts(privateKey string, t string) (*Contracts, error) {
	// Perform signing using private key
	privKey, err := crypto.ToPrivKey(privateKey)
	if err != nil {
		return nil, err
	}
	for idx, element := range c.Contracts {
		by, err := cutils.StringToBytes(element.Contract, cutils.Base64)
		if err != nil {
			return nil, err
		}
		var signedContract []byte
		if t == "escrow" {
			escrowContract := &escrowpb.EscrowContract{}
			err = proto.Unmarshal(by, escrowContract)
			if err != nil {
				return nil, err
			}
			signedContract, err = crypto.Sign(privKey, escrowContract)
			if err != nil {
				return nil, err
			}

		} else if t == "guard" {
			guardContract := &guardpb.ContractMeta{}
			err := proto.Unmarshal(by, guardContract)
			if err != nil {
				return nil, err
			}
			signedContract, err = crypto.Sign(privKey, guardContract)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("not support type:" + t)
		}
		// This overwrites
		str, err := cutils.BytesToString(signedContract, cutils.Base64)
		if err != nil {
			return nil, err
		}
		c.Contracts[idx].Contract = str
		if err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// Set storage upload time.
func StorageLength(length int) StorageUploadOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("storage-length", length)
		return nil
	}
}

func (s *Shell) GetUts() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func NewSessionSignature(hash string, peerIdStr string, uts string, verifyBefore bool) (string, error) {
	// Create offline session signature input data
	inputDataStr := fmt.Sprintf("%s%s%s", hash, peerIdStr, uts)

	// Sign sessionSignature
	privKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return "", err
	}

	sig, err := privKey.Sign([]byte(inputDataStr))
	if err != nil {
		return "", err
	}

	sigStr, err := cutils.BytesToString(sig, cutils.Base64)
	if err != nil {
		return "", err
	}
	utils.SetSessionSignature(sigStr)

	peerId, err := peer.IDFromBytes([]byte(utils.GetPeerId()))
	if err != nil {
		return "", err
	}

	if verifyBefore {
		err = VerifySessionSignature(peerId, inputDataStr, sigStr)
		if err != nil {
			return "", err
		}
	}

	return sigStr, nil
}

func VerifySessionSignature(offSignRenterPid peer.ID, data string, sessionSigStr string) error {
	// get renter's public key
	pubKey, err := offSignRenterPid.ExtractPublicKey()
	if err != nil {
		return err
	}

	sigBytes, err := cutils.StringToBytes(sessionSigStr, cutils.Base64)
	if err != nil {
		return err
	}
	ok, err := pubKey.Verify([]byte(data), sigBytes)
	if !ok || err != nil {
		return fmt.Errorf("can't verify session signature: %v", err)
	}
	return nil
}

func getSessionSignature() (string, error) {
	if utils.ApiConfig.SessionSignature == "" {
		return "", errors.New("API session signature is not yet created. NewSessionSignature() should be called.")
	}
	return utils.GetSessionSignature(), nil
}

// Storage upload api.
func (s *Shell) StorageUpload(hash string, options ...StorageUploadOpts) (string, error) {
	var out storageUploadResponse
	rb := s.Request("storage/upload", hash)
	for _, option := range options {
		_ = option(rb)
	}
	return out.ID, rb.Exec(context.Background(), &out)
}

// Storage upload api.
func (s *Shell) StorageUploadOffSign(hash string, uts string, options ...StorageUploadOpts) (string, error) {
	var out storageUploadResponse
	offlinePeerSessionSignature, err := NewSessionSignature(hash, utils.GetPeerId(), uts, false)
	if err != nil {
		return "", err
	}
	rb := s.Request("storage/upload", hash, utils.GetPeerId(), uts, offlinePeerSessionSignature)
	for _, option := range options {
		_ = option(rb)
	}
	return out.ID, rb.Exec(context.Background(), &out)
}

// Storage upload status api.
func (s *Shell) StorageUploadStatus(id string) (*Storage, error) {
	var out Storage
	rb := s.Request("storage/upload/status", id)
	return &out, rb.Exec(context.Background(), &out)
}

// Storage upload get offline contract batch api.
func (s *Shell) StorageUploadGetContractBatch(sid string, uts string, t string) (*Contracts, error) {
	var out Contracts
	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return nil, err
	}
	rb := s.Request("storage/upload/getcontractbatch", sid, utils.GetPeerId(), uts, offlinePeerSessionSignature, t)
	return &out, rb.Exec(context.Background(), &out)
}

// Storage upload get offline unsigned data api.
func (s *Shell) StorageUploadGetUnsignedData(sid string, uts string, sessionStatus string) (*UnsignedData, error) {
	var out UnsignedData
	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return nil, err
	}
	rb := s.Request("storage/upload/getunsigned", sid, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus)
	return &out, rb.Exec(context.Background(), &out)
}

// Storage upload sign offline contract batch api.
func (s *Shell) StorageUploadSignBatch(sid string, unsignedBatchContracts *Contracts, uts string, t string) error {
	var signedBatchContracts *Contracts
	var errSign error
	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}

	signedBatchContracts, errSign = unsignedBatchContracts.SignContracts(utils.GetPrivateKey(), t)
	if errSign != nil {
		return err
	}
	bytesSignBatch, err := json.Marshal(signedBatchContracts.Contracts)
	if err != nil {
		return err
	}

	rb := s.Request("storage/upload/signcontractbatch", sid, utils.GetPeerId(), uts, offlinePeerSessionSignature,
		t, string(bytesSignBatch))
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	errSign = rb.Exec(ctx, nil)
	return errSign
}

// Storage upload sign offline data api.
func (s *Shell) StorageUploadSign(id string, hash string, unsignedData *UnsignedData, uts string, sessionStatus string) ([]byte, error) {
	var out []byte
	var rb *RequestBuilder
	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return nil, err
	}
	signedBytes, err := unsignedData.SignData(utils.GetPrivateKey())
	if err != nil {
		return nil, err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, string(signedBytes), sessionStatus)
	return out, rb.Exec(context.Background(), &out)
}

func (s *Shell) StorageUploadSignBalance(id string, unsignedData *UnsignedData, uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}

	ledgerSignedPublicKey, err := unsignedData.SignBalanceData(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	signedBytes, err := proto.Marshal(ledgerSignedPublicKey) // TODO: check if ic.Marshall is necessary!
	if err != nil {
		return err
	}
	str, err := cutils.BytesToString(signedBytes, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus, str)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignPayChannel(id string, unsignedData *UnsignedData, uts string, sessionStatus string,
	totalPrice int64) error {
	var rb *RequestBuilder
	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}

	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	escrowPubKey, err := ic.UnmarshalPublicKey(unsignedBytes)
	if err != nil {
		return err
	}
	buyerPubKey, err := crypto.ToPubKey(utils.GetPublicKey())
	if err != nil {
		return err
	}
	fromAddr, err := ic.MarshalPublicKey(buyerPubKey)
	if err != nil {
		return err
	}
	toAddr, err := ic.MarshalPublicKey(escrowPubKey)
	if err != nil {
		return err
	}
	chanCommit := &ledgerpb.ChannelCommit{
		Payer:     &ledgerpb.PublicKey{Key: fromAddr},
		Recipient: &ledgerpb.PublicKey{Key: toAddr},
		Amount:    totalPrice,
		PayerId:   time.Now().UnixNano(),
	}
	buyerPrivKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	buyerChanSig, err := crypto.Sign(buyerPrivKey, chanCommit)
	if err != nil {
		return err
	}
	signedChanCommit := &ledgerpb.SignedChannelCommit{
		Channel:   chanCommit,
		Signature: buyerChanSig,
	}
	signedChanCommitBytes, err := proto.Marshal(signedChanCommit)
	if err != nil {
		return err
	}
	signedChanCommitBytesStr, err := cutils.BytesToString(signedChanCommitBytes, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus,
		signedChanCommitBytesStr)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignPayRequest(id string, unsignedData *UnsignedData, uts string,
	sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}

	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	result := new(escrowpb.SignedSubmitContractResult)
	err = proto.Unmarshal(unsignedBytes, result)
	if err != nil {
		return err
	}

	chanState := result.Result.BuyerChannelState
	privKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(privKey, chanState.Channel)
	if err != nil {
		return err
	}
	chanState.FromSignature = sig
	payerPubKey, _ := crypto.ToPubKey(utils.GetPublicKey())
	raw, err := ic.MarshalPublicKey(payerPubKey)
	if err != nil {
		return err
	}
	payinReq := &escrowpb.PayinRequest{
		PayinId:           result.Result.PayinId,
		BuyerAddress:      raw,
		BuyerChannelState: chanState,
	}
	payinSig, err := crypto.Sign(privKey, payinReq)
	if err != nil {
		return err
	}
	signedPayinReq := &escrowpb.SignedPayinRequest{
		Request:        payinReq,
		BuyerSignature: payinSig,
	}

	signedPayinReqBytes, err := proto.Marshal(signedPayinReq)
	if err != nil {
		return err
	}

	str, err := cutils.BytesToString(signedPayinReqBytes, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus, str)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignGuardFileMeta(id string, unsignedData *UnsignedData,
	uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}
	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	meta := new(guardpb.FileStoreMeta)
	err = proto.Unmarshal(unsignedBytes, meta)
	if err != nil {
		return err
	}

	privKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	signed, err := crypto.Sign(privKey, meta)
	if err != nil {
		return err
	}

	str, err := cutils.BytesToString(signed, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus, str)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignGuardQuestions(id string, unsignedData *UnsignedData,
	uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}
	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	fcq := new(guardpb.FileChallengeQuestions)
	err = proto.Unmarshal(unsignedBytes, fcq)
	if err != nil {
		return err
	}

	privKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	for _, sq := range fcq.ShardQuestions {
		sign, err := crypto.Sign(privKey, sq)
		if err != nil {
			return err
		}
		sq.PreparerSignature = sign
	}

	signed, err := proto.Marshal(fcq)
	if err != nil {
		return err
	}
	str, err := cutils.BytesToString(signed, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus, str)
	return rb.Exec(context.Background(), nil)
}

func (s *Shell) StorageUploadSignWaitupload(id string, unsignedData *UnsignedData,
	uts string, sessionStatus string) error {
	var rb *RequestBuilder

	offlinePeerSessionSignature, err := getSessionSignature()
	if err != nil {
		return err
	}
	unsignedBytes, err := cutils.StringToBytes(unsignedData.Unsigned, cutils.Base64)
	if err != nil {
		return err
	}
	meta := new(guardpb.CheckFileStoreMetaRequest)
	err = proto.Unmarshal(unsignedBytes, meta)
	if err != nil {
		return err
	}

	privKey, err := crypto.ToPrivKey(utils.GetPrivateKey())
	if err != nil {
		return err
	}
	signed, err := crypto.Sign(privKey, meta)
	if err != nil {
		return err
	}

	str, err := cutils.BytesToString(signed, cutils.Base64)
	if err != nil {
		return err
	}
	rb = s.Request("storage/upload/sign", id, utils.GetPeerId(), uts, offlinePeerSessionSignature, sessionStatus, str)
	return rb.Exec(context.Background(), nil)
}
